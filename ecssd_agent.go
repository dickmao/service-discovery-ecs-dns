package main

// Copyright 2016-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
// http://aws.amazon.com/apache2.0/
// or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

import (
	"flag"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"context"
	"io"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchevents"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

const workerTimeout = 180 * time.Second
const defaultTTL = 0
const defaultWeight = 1

var DNSName = "servicediscovery.internal"

type handler interface {
	Handle(events.Message) error
}

type dockerRouter struct {
	handlers      map[string][]handler
	dockerClient  *docker.Client
	cancel        context.CancelFunc
	events        <-chan events.Message
	errors        <-chan error
	workers       chan *worker
	workerTimeout time.Duration
}

func dockerEventsRouter(workerPoolSize int, dockerClient *docker.Client,
	handlers map[string][]handler) (*dockerRouter, error) {
	workers := make(chan *worker, workerPoolSize)
	for i := 0; i < workerPoolSize; i++ {
		workers <- &worker{}
	}

	dockerRouter := &dockerRouter{
		handlers:      handlers,
		dockerClient:  dockerClient,
		workers:       workers,
		workerTimeout: workerTimeout,
	}

	return dockerRouter, nil
}

func (e *dockerRouter) start() {
	var ctx context.Context
	ctx, e.cancel = context.WithCancel(context.Background())
	filters := filters.NewArgs()
	filters.Add("Type", events.ContainerEventType)
	e.events, e.errors = e.dockerClient.Events(ctx, types.EventsOptions{Filters: filters})
	go e.manageEvents()
}

func (e *dockerRouter) stop() {
	e.cancel()
}

func (e *dockerRouter) manageEvents() {
	for {
		select {
		case err := <-e.errors:
			if err != nil && err != io.EOF {
				logErrorAndFail(err)
			}
		case event := <-e.events:
			timer := time.NewTimer(e.workerTimeout)
			gotWorker := false
			// Wait until we get a free worker or a timeout
			// there is a limit in the number of concurrent events managed by workers to avoid resource exhaustion
			// so we wait until we have a free worker or a timeout occurs
			for !gotWorker {
				select {
				case w := <-e.workers:
					if !timer.Stop() {
						<-timer.C
					}
					go w.doWork(event, e)
					gotWorker = true
				case <-timer.C:
					log.Infof("Timed out waiting.")
				}
			}

		}
	}
}

type worker struct{}

func (w *worker) doWork(event events.Message, e *dockerRouter) {
	defer func() { e.workers <- w }()
	if handlers, ok := e.handlers[event.Action]; ok {
		log.Infof("Processing event: %#v", event)
		for _, handler := range handlers {
			if err := handler.Handle(event); err != nil {
				log.Errorf("Error processing event %#v. Error: %v", event, err)
			}
		}
	}
}

type dockerHandler struct {
	handlerFunc func(event events.Message) error
}

func (th *dockerHandler) Handle(event events.Message) error {
	return th.handlerFunc(event)
}

type config struct {
	HostedZoneId string
	Hostname     string
	Region       string
}

var configuration config

func logErrorAndFail(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func logErrorNoFatal(err error) {
	if err != nil {
		log.Error(err)
	}
}

type topTasks struct {
	Tasks []taskInfo
}

type taskInfo struct {
	Arn           string
	DesiredStatus string
	KnownStatus   string
	Family        string
	Version       string
	Containers    []ContainerInfo
}

type ContainerInfo struct {
	DockerId   string
	DockerName string
	Name       string
}

type ServiceInfo struct {
	Name string
	Port string
}

func getDNSHostedZoneId() (string, error) {
	sess, err := session.NewSession()
	if err != nil {
		return "", err
	}
	r53 := route53.New(sess)
	params := &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(DNSName),
	}

	zones, err := r53.ListHostedZonesByName(params)

	if err == nil {
		if len(zones.HostedZones) > 0 {
			return aws.StringValue(zones.HostedZones[0].Id), nil
		}
	}

	return "", err
}

func createSrvRecordSet(dockerId, port, serviceName string) *route53.ResourceRecordSet {
	srvRecordName := serviceName + "." + DNSName

	return &route53.ResourceRecordSet{
		Name: aws.String(srvRecordName),
		// It creates a SRV record with the name of the service
		Type: aws.String(route53.RRTypeSrv),
		ResourceRecords: []*route53.ResourceRecord{
			{
				// priority: the priority of the target host, lower value means more preferred
				// weight: A relative weight for records with the same priority, higher value means more preferred
				// port: the TCP or UDP port on which the service is to be found
				// target: the canonical hostname of the machine providing the service
				Value: aws.String("1 1 " + port + " " + configuration.Hostname),
			},
		},
		SetIdentifier: aws.String(configuration.Hostname + ":" + dockerId),
		// TTL=0 to avoid DNS caches
		TTL:    aws.Int64(defaultTTL),
		Weight: aws.Int64(defaultWeight),
	}
}

func createARecordSet(hostName, localIP, setidentifier string) *route53.ResourceRecordSet {
	return &route53.ResourceRecordSet{
		Name: aws.String(strings.Split(hostName, ".")[0] + "." + DNSName),
		// It creates an A record with the IP of the host running the agent
		Type: aws.String(route53.RRTypeA),
		ResourceRecords: []*route53.ResourceRecord{
			{
				Value: aws.String(localIP),
			},
		},
		SetIdentifier: aws.String(setidentifier),
		// TTL=0 to avoid DNS caches
		TTL:    aws.Int64(defaultTTL),
		Weight: aws.Int64(defaultWeight),
	}
}

func deleteRecordSetsFor(serviceName string, dockerId string) []*route53.ResourceRecordSet {
	srvSetIdentifier := configuration.Hostname + ":" + dockerId

	paramsList := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(configuration.HostedZoneId), // Required
		MaxItems:     aws.String("100"),
	}
	sess, err := session.NewSession()
	logErrorAndFail(err)
	r53 := route53.New(sess)
	resp, err := r53.ListResourceRecordSets(paramsList)

	more := true
	toDel := make([]*route53.ResourceRecordSet, 0, 100)
	for more && err == nil {
		for _, rrs := range resp.ResourceRecordSets {
			if isManagedResourceRecordSet(rrs) && *rrs.SetIdentifier == srvSetIdentifier {
				log.Infof("Removing %s record %s %s", *rrs.Type, *rrs.Name, *rrs.ResourceRecords[0].Value)
				toDel = append(toDel, rrs)
			}
		}

		more = resp.IsTruncated != nil && *resp.IsTruncated
		if more {
			paramsList.StartRecordIdentifier = resp.NextRecordIdentifier
			resp, err = r53.ListResourceRecordSets(paramsList)
		}
	}
	logErrorNoFatal(err)
	return toDel
}

var dockerClient *docker.Client

func isManagedResourceRecordSet(rrs *route53.ResourceRecordSet) bool {
	return rrs != nil &&
		rrs.Type != nil &&
		*rrs.Type != route53.RRTypeSoa &&
		*rrs.Type != route53.RRTypeNs &&
		rrs.SetIdentifier != nil &&
		strings.HasPrefix(*rrs.SetIdentifier, configuration.Hostname)
}

// Synchronizes the service records of the hosted zone against the currently running docker instances.
// SRV records associated with containers on this host which are no longer running, will be removed.
// Missing SRV records from running containers are added.
func syncDNSRecords() error {
	containers, err := dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return err
	}

	sess, err := session.NewSession()
	if err != nil {
		return err
	}
	r53 := route53.New(sess)

	inZone := map[string][]*route53.ResourceRecordSet{}

	paramsList := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(configuration.HostedZoneId), // Required
		MaxItems:     aws.String("100"),
	}
	more := true
	resp, err := r53.ListResourceRecordSets(paramsList)
	for more && err == nil {
		for _, rrset := range resp.ResourceRecordSets {
			if isManagedResourceRecordSet(rrset) {
				inZone[*rrset.SetIdentifier] = append(inZone[*rrset.SetIdentifier], rrset)
			}
		}

		more = resp.IsTruncated != nil && *resp.IsTruncated
		if more {
			paramsList.StartRecordIdentifier = resp.NextRecordIdentifier
			resp, err = r53.ListResourceRecordSets(paramsList)
		}
	}

	running := make(map[string]string, len(containers)+1)
	running[configuration.Hostname] = ""
	for _, container := range containers {
		running[configuration.Hostname+":"+container.ID] = container.ID
	}

	toDelete := map[string][]*route53.ResourceRecordSet{}
	for k, v := range inZone {
		if _, ok := running[k]; !ok {
			toDelete[k] = v
		}
	}

	maybeAdd := map[string]string{}
	for k, v := range running {
		if _, ok := inZone[k]; !ok {
			maybeAdd[k] = v
		}
	}

	changes := make([]*route53.Change, 0, 100)

	for _, arr_rs := range toDelete {
		for _, rs := range arr_rs {
			log.Infof("Removing %s record %s %s", *rs.Type, *rs.Name, *rs.ResourceRecords[0].Value)
			changes = append(changes, &route53.Change{
				Action:            aws.String(route53.ChangeActionDelete),
				ResourceRecordSet: rs,
			})
		}
	}

	for _, id := range maybeAdd {
		container, err := dockerClient.ContainerInspect(context.Background(), id)
		if err != nil {
			continue
		}
		for _, svc := range getNetworkPortAndServiceName(container, true) {
			if svc.Name != "" && svc.Port != "" {
				rrs := createSrvRecordSet(id, svc.Port, svc.Name)
				log.Infof("Adding %s record %s %s", *rrs.Type, *rrs.Name, *rrs.ResourceRecords[0].Value)
				changes = append(changes, &route53.Change{
					Action:            aws.String(route53.ChangeActionUpsert),
					ResourceRecordSet: rrs,
				})
			}
		}
	}

	if len(changes) > 0 {
		_, err = r53.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
			ChangeBatch: &route53.ChangeBatch{
				Comment: aws.String("Sync DNS Records"),
				Changes: changes,
			},
			HostedZoneId: aws.String(configuration.HostedZoneId),
		})
		logErrorNoFatal(err)
		return err
	}

	return nil
}

// Remove all SRV records from the hosted zone associated with this host. Run this on the shutdown event of the host.
func removeAllManagedRecords() {
	sess, err := session.NewSession()
	logErrorAndFail(err)
	r53 := route53.New(sess)

	changes := make([]*route53.Change, 0)

	paramsList := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(configuration.HostedZoneId), // Required
		MaxItems:     aws.String("100"),
	}
	more := true
	resp, err := r53.ListResourceRecordSets(paramsList)
	for more && err == nil {
		for _, rrset := range resp.ResourceRecordSets {
			if isManagedResourceRecordSet(rrset) {
				log.Infof("Removing %s record %s %s", *rrset.Type, *rrset.Name, *rrset.ResourceRecords[0].Value)
				changes = append(changes, &route53.Change{
					Action:            aws.String(route53.ChangeActionDelete),
					ResourceRecordSet: rrset,
				})
			}
		}

		more = resp.IsTruncated != nil && *resp.IsTruncated
		if more {
			paramsList.StartRecordIdentifier = resp.NextRecordIdentifier
			resp, err = r53.ListResourceRecordSets(paramsList)
		}
	}

	if len(changes) > 0 {
		_, err = r53.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
			ChangeBatch: &route53.ChangeBatch{
				Comment: aws.String("Service Discovery Created Record"),
				Changes: changes,
			},
			HostedZoneId: aws.String(configuration.HostedZoneId),
		})
		logErrorNoFatal(err)
	}
}

func getNetworkPortAndServiceName(container types.ContainerJSON, includePort bool) []ServiceInfo {
	// One of the environment variables should be SERVICE_<port>_NAME = <name of the service>
	// We look for this environment variable doing a split in the "=" and another one in the "_"
	// So envEval = [SERVICE_<port>_NAME, <name>]
	// nameEval = [SERVICE, <port>, NAME]
	var svc []ServiceInfo = make([]ServiceInfo, 0)
	for _, env := range container.Config.Env {
		envEval := strings.Split(env, "=")
		nameEval := strings.Split(envEval[0], "_")
		if len(envEval) == 2 && len(nameEval) == 3 && nameEval[0] == "SERVICE" && nameEval[2] == "NAME" {
			if _, err := strconv.Atoi(nameEval[1]); err == nil {
				if includePort {
					for srcPort, mapping := range container.NetworkSettings.Ports {
						portEval := strings.Split(string(srcPort), "/")
						if len(portEval) > 0 && portEval[0] == nameEval[1] {
							if len(mapping) > 0 {
								svc = append(svc, ServiceInfo{envEval[1], mapping[0].HostPort})
							}
						}
					}
				} else {
					svc = append(svc, ServiceInfo{envEval[1], ""})
				}
			}
		}
	}
	return svc
}

func sendToCWEvents(detail string, detailType string, resource string, source string) error {
	config := aws.NewConfig().WithRegion(configuration.Region)
	sess, err := session.NewSession(config)
	if err != nil {
		return err
	}
	svc := cloudwatchevents.New(sess)
	params := &cloudwatchevents.PutEventsInput{
		Entries: []*cloudwatchevents.PutEventsRequestEntry{
			{
				Detail:     aws.String(detail),
				DetailType: aws.String(detailType),
				Resources: []*string{
					aws.String(resource),
				},
				Source: aws.String(source),
				Time:   aws.Time(time.Now()),
			},
		},
	}
	_, err = svc.PutEvents(params)
	logErrorNoFatal(err)
	return err
}

func getTaskArn(dockerID string) string {
	resp, err := http.Get("http://127.0.0.1:51678/v1/tasks")
	logErrorAndFail(err)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)
	idIndex := strings.Index(bodyStr, string(dockerID))
	arnStartIndex := strings.LastIndex(bodyStr[:idIndex], "arn:aws:ecs:")
	arnString := bodyStr[arnStartIndex:]
	arnEndIndex := strings.Index(arnString, "\"")
	return arnString[:arnEndIndex]
}

func tryBackoff(tryme func() (interface{}, error)) (interface{}, error) {
	var result interface{}
	var err error
	var sum = 1
	for {
		result, err = tryme()
		if err == nil {
			break
		}
		if sum > 8 {
			break
		}
		time.Sleep(time.Duration(sum) * time.Second)
		sum += 2
	}
	return result, err
}

func main() {
	sendEvents := flag.Bool("cw-send-events", false, "Send CloudWatch events when a container is created or terminated")
	remove := flag.Bool("remove", false, "Remove all DNS records associated with this instance")
	sync := flag.Bool("sync", false, "Synchronize this instance and exit")
	hostnameOverride := flag.String("hostname", "", "to use for registering the SRV records")

	flag.Parse()

	DNSNameArg := flag.Arg(0)
	if DNSNameArg != "" {
		DNSName = DNSNameArg
	}

	zoneId, err := tryBackoff(func() (interface{}, error) { return getDNSHostedZoneId() })
	if err != nil {
		logErrorAndFail(err)
	}

	configuration.HostedZoneId = zoneId.(string)

	sess, err := session.NewSession()
	logErrorAndFail(err)
	metadataClient := ec2metadata.New(sess)

	if *hostnameOverride == "" {
		hostname, err := metadataClient.GetMetadata("/hostname")
		logErrorAndFail(err)

		name := strings.Split(strings.TrimSpace(hostname), " ")
		if len(name) > 1 {
			log.Errorf("metadata returned '%s' as hostname which contains spaces. using first '%s'", hostname, name[0])
		}
		configuration.Hostname = name[0]
	} else {
		configuration.Hostname = *hostnameOverride
	}

	localIP, err := metadataClient.GetMetadata("/local-ipv4")
	logErrorAndFail(err)

	region, err := metadataClient.Region()
	configuration.Region = region
	logErrorAndFail(err)

	if *remove {
		removeAllManagedRecords()
		os.Exit(0)
	}

	dockerClient, _ = docker.NewEnvClient()

	err = syncDNSRecords()
	logErrorNoFatal(err)

	if *sync {
		os.Exit(0)
	}

	r53 := route53.New(sess)

	_, err = r53.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action:            aws.String(route53.ChangeActionUpsert),
					ResourceRecordSet: createARecordSet(configuration.Hostname, localIP, configuration.Hostname),
				},
			},
			Comment: aws.String("Host A Record Upsert"),
		},
		HostedZoneId: aws.String(configuration.HostedZoneId),
	})
	logErrorNoFatal(err)
	if err == nil {
		log.Info("Record " + configuration.Hostname + " created, resolves to " + localIP)
	} else {
		log.Error("Record " + configuration.Hostname + " not created, resolves to " + localIP)
	}

	startFn := func(event events.Message) error {
		var err error
		container, err := dockerClient.ContainerInspect(context.Background(), event.ID)
		logErrorAndFail(err)

		changes := make([]*route53.Change, 0, 2)
		for _, svc := range getNetworkPortAndServiceName(container, true) {
			if svc.Name != "" && svc.Port != "" {
				srs, err := tryBackoff(func() (interface{}, error) { return createSrvRecordSet(event.ID, svc.Port, svc.Name), nil })
				if err != nil {
					log.Error("Error creating SRV record set")
				} else {
					var casted *route53.ResourceRecordSet = srs.(*route53.ResourceRecordSet)
					log.Infof("Adding %s record %s %s", *casted.Type, *casted.Name, *casted.ResourceRecords[0].Value)
					changes = append(changes, &route53.Change{
						Action:            aws.String(route53.ChangeActionCreate),
						ResourceRecordSet: casted,
					})
				}

				ars, err := tryBackoff(func() (interface{}, error) {
					return createARecordSet(strings.TrimLeft(svc.Name, "_"), localIP, configuration.Hostname+":"+event.ID), nil
				})
				if err != nil {
					log.Error("Error creating A record set")
				} else {
					var casted *route53.ResourceRecordSet = ars.(*route53.ResourceRecordSet)
					log.Infof("Adding %s record %s %s", *casted.Type, *casted.Name, *casted.ResourceRecords[0].Value)
					changes = append(changes, &route53.Change{
						Action:            aws.String(route53.ChangeActionUpsert),
						ResourceRecordSet: casted,
					})
				}
			}
		}

		if len(changes) > 0 {
			_, err = r53.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
				ChangeBatch: &route53.ChangeBatch{
					Comment: aws.String("Service Start DNS Records"),
					Changes: changes,
				},
				HostedZoneId: aws.String(configuration.HostedZoneId),
			})
			logErrorNoFatal(err)
		}

		if *sendEvents {
			taskArn := getTaskArn(event.ID)
			sendToCWEvents(`{ "dockerId": "`+event.ID+`","TaskArn":"`+taskArn+`" }`, "Task Started", configuration.Hostname, "awslabs.ecs.container")
		}

		log.Info("Docker " + event.ID + " started")
		return nil
	}

	stopFn := func(event events.Message) error {
		var err error
		container, err := dockerClient.ContainerInspect(context.Background(), event.ID)
		logErrorAndFail(err)

		changes := make([]*route53.Change, 0, 2)
		for _, svc := range getNetworkPortAndServiceName(container, false) {
			if svc.Name != "" {
				rss, err := tryBackoff(func() (interface{}, error) { return deleteRecordSetsFor(svc.Name, event.ID), nil })
				if err != nil {
					log.Error("Error collecting record sets to delete")
				} else {
					for _, rs := range rss.([]*route53.ResourceRecordSet) {
						changes = append(changes, &route53.Change{
							Action:            aws.String(route53.ChangeActionDelete),
							ResourceRecordSet: rs,
						})
					}
				}
			}
		}
		if *sendEvents {
			taskArn := getTaskArn(event.ID)
			sendToCWEvents(`{ "dockerId": "`+event.ID+`","TaskArn":"`+taskArn+`" }`, "Task Stopped", configuration.Hostname, "awslabs.ecs.container")
		}
		log.Info("Docker " + event.ID + " stopped")
		return nil
	}

	startHandler := &dockerHandler{
		handlerFunc: startFn,
	}
	stopHandler := &dockerHandler{
		handlerFunc: stopFn,
	}
	handlers := map[string][]handler{"start": {startHandler}, "die": {stopHandler}}

	router, err := dockerEventsRouter(5, dockerClient, handlers)
	logErrorAndFail(err)
	defer router.stop()
	router.start()
	log.Info("Waiting events")
	select {}
}
