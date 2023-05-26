package leakybucket

import "github.com/asians-cloud/crowdsec/pkg/types"

type Processor interface {
	OnBucketInit(Bucket *BucketFactory) error
	OnBucketPour(Bucket *BucketFactory) func(types.Event, *Leaky) *types.Event
	OnBucketOverflow(Bucket *BucketFactory) func(*Leaky, types.RuntimeAlert, *Queue) (types.RuntimeAlert, *Queue)

	AfterBucketPour(Bucket *BucketFactory) func(types.Event, *Leaky) *types.Event
}

type DumbProcessor struct {
}

func (d *DumbProcessor) OnBucketInit(bucketFactory *BucketFactory) error {
	return nil
}

func (d *DumbProcessor) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		return &msg
	}
}

func (d *DumbProcessor) OnBucketOverflow(b *BucketFactory) func(*Leaky, types.RuntimeAlert, *Queue) (types.RuntimeAlert, *Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *Queue) (types.RuntimeAlert, *Queue) {
		return alert, queue
	}
}

func (d *DumbProcessor) AfterBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		return &msg
	}
}
