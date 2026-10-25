package docker

import (
	"testing"

	"github.com/moby/moby/api/types/events"
)

func TestConvert(t *testing.T) {
	tests := []struct {
		msg  events.Message
		want Event
		ok   bool
	}{
		{events.Message{Type: events.ContainerEventType, Action: events.ActionStart, Actor: events.Actor{ID: "c1"}}, Event{EventStart, "c1"}, true},
		{events.Message{Type: events.ContainerEventType, Action: events.ActionDie, Actor: events.Actor{ID: "c1"}}, Event{EventDie, "c1"}, true},
		{events.Message{Type: events.NetworkEventType, Action: events.ActionConnect, Actor: events.Actor{ID: "n1", Attributes: map[string]string{"container": "c2"}}}, Event{EventNetwork, "c2"}, true},
		{events.Message{Type: events.NetworkEventType, Action: events.ActionDisconnect, Actor: events.Actor{ID: "n1"}}, Event{}, false},
		{events.Message{Type: events.ContainerEventType, Action: events.ActionStop, Actor: events.Actor{ID: "c1"}}, Event{}, false},
	}
	for _, tt := range tests {
		got, ok := convert(tt.msg)
		if ok != tt.ok || got != tt.want {
			t.Errorf("convert(%s %s) = %v %v, want %v %v", tt.msg.Type, tt.msg.Action, got, ok, tt.want, tt.ok)
		}
	}
}

func TestInfoModes(t *testing.T) {
	for mode, want := range map[string][3]bool{
		"host":           {true, false, false},
		"none":           {false, true, false},
		"container:abcd": {false, false, true},
		"fw":             {false, false, false},
	} {
		i := Info{NetworkMode: mode}
		if got := [3]bool{i.HostNetwork(), i.NoNetwork(), i.SharedNetwork()}; got != want {
			t.Errorf("%s: got %v want %v", mode, got, want)
		}
	}
	if !(&Info{CapAdd: []string{"cap_net_admin"}}).HasNetAdmin() || !(&Info{CapAdd: []string{"ALL"}}).HasNetAdmin() ||
		!(&Info{Privileged: true}).HasNetAdmin() || (&Info{CapAdd: []string{"NET_RAW"}}).HasNetAdmin() {
		t.Error("HasNetAdmin")
	}
}
