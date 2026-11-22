package sandbox

import (
	"encoding/json"
	"testing"
)

func TestTraceBufferFiltersAndEvicts(t *testing.T) {
	buffer := newTraceBuffer(2)
	buffer.add("container-a", []byte(`{"containerId":"container-a","eventName":"one"}`))
	buffer.add("", []byte(`{"containerId":"","eventName":"host"}`))
	buffer.add("container-a", []byte(`{"containerId":"container-a","eventName":"two"}`))
	buffer.add("container-b", []byte(`{"containerId":"container-b","eventName":"three"}`))

	events, total := buffer.since(1, "container-a", 10)
	if total != 1 || len(events) != 1 {
		t.Fatalf("container-a total=%d events=%d", total, len(events))
	}
	var event map[string]any
	if err := json.Unmarshal(events[0], &event); err != nil {
		t.Fatal(err)
	}
	if event["eventName"] != "two" || event["collector"] != "tracee" {
		t.Fatalf("event = %#v", event)
	}

	all, total := buffer.since(1, "", 10)
	if total != 2 || len(all) != 2 {
		t.Fatalf("all total=%d events=%d", total, len(all))
	}
	if buffer.sequence() != 4 {
		t.Fatalf("sequence = %d", buffer.sequence())
	}
}

func TestTraceBufferSinceSkipsOldEvents(t *testing.T) {
	buffer := newTraceBuffer(10)
	buffer.add("a", []byte(`{"containerId":"a","eventName":"old"}`))
	sequence := buffer.sequence()
	buffer.add("a", []byte(`{"containerId":"a","eventName":"new"}`))
	events, total := buffer.since(sequence, "a", 10)
	if total != 1 || len(events) != 1 {
		t.Fatalf("total=%d events=%d", total, len(events))
	}
}
