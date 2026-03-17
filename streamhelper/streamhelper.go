package streamhelper

import (
	"maunium.net/go/mautrix"
)

type HelperOptions = mautrix.StreamHelperOptions
type SubscribeRequest = mautrix.StreamSubscribeRequest
type GeneratorOptions = mautrix.StreamGeneratorOptions
type StreamDescriptorRequest = mautrix.StreamDescriptorRequest
type StartRequest = mautrix.StartStreamRequest
type PublishRequest = mautrix.PublishStreamRequest
type FinishRequest = mautrix.FinishStreamRequest
type Helper = mautrix.StreamHelper
type Generator = mautrix.StreamGenerator

func New(client *mautrix.Client, opts *HelperOptions) *Helper {
	return mautrix.NewStreamHelper(client, opts)
}
