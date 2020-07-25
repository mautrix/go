// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"fmt"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

var allEmojis = [...]VerificationEmoji{
	{'🐶', "Dog"},
	{'🐱', "Cat"},
	{'🦁', "Lion"},
	{'🐎', "Horse"},
	{'🦄', "Unicorn"},
	{'🐷', "Pig"},
	{'🐘', "Elephant"},
	{'🐰', "Rabbit"},
	{'🐼', "Panda"},
	{'🐓', "Rooster"},
	{'🐧', "Penguin"},
	{'🐢', "Turtle"},
	{'🐟', "Fish"},
	{'🐙', "Octopus"},
	{'🦋', "Butterfly"},
	{'🌷', "Flower"},
	{'🌳', "Tree"},
	{'🌵', "Cactus"},
	{'🍄', "Mushroom"},
	{'🌏', "Globe"},
	{'🌙', "Moon"},
	{'☁', "Cloud"},
	{'🔥', "Fire"},
	{'🍌', "Banana"},
	{'🍎', "Apple"},
	{'🍓', "Strawberry"},
	{'🌽', "Corn"},
	{'🍕', "Pizza"},
	{'🎂', "Cake"},
	{'❤', "Heart"},
	{'😀', "Smiley"},
	{'🤖', "Robot"},
	{'🎩', "Hat"},
	{'👓', "Glasses"},
	{'🔧', "Spanner"},
	{'🎅', "Santa"},
	{'👍', "Thumbs Up"},
	{'☂', "Umbrella"},
	{'⌛', "Hourglass"},
	{'⏰', "Clock"},
	{'🎁', "Gift"},
	{'💡', "Light Bulb"},
	{'📕', "Book"},
	{'✏', "Pencil"},
	{'📎', "Paperclip"},
	{'✂', "Scissors"},
	{'🔒', "Lock"},
	{'🔑', "Key"},
	{'🔨', "Hammer"},
	{'☎', "Telephone"},
	{'🏁', "Flag"},
	{'🚂', "Train"},
	{'🚲', "Bicycle"},
	{'✈', "Aeroplane"},
	{'🚀', "Rocket"},
	{'🏆', "Trophy"},
	{'⚽', "Ball"},
	{'🎸', "Guitar"},
	{'🎺', "Trumpet"},
	{'🔔', "Bell"},
	{'⚓', "Anchor"},
	{'🎧', "Headphones"},
	{'📁', "Folder"},
	{'📌', "Pin"},
}

// VerificationEmoji describes an emoji that might be sent for verifying devices.
type VerificationEmoji struct {
	Emoji       rune
	Description string
}

// GetSASVerificationNumbers generates the three numbers that need to match with the other device for a verification to be valid.
func (mach *OlmMachine) GetSASVerificationNumbers(initUserID id.UserID, initDeviceID id.DeviceID, initKey string,
	acceptUserID id.UserID, acceptDeviceID id.DeviceID, acceptKey string,
	transactionID string, sas *olm.SAS) ([3]uint, error) {
	sasInfo := fmt.Sprintf("MATRIX_KEY_VERIFICATION_SAS|%s|%s|%s|%s|%s|%s|%s",
		initUserID, initDeviceID, initKey,
		acceptUserID, acceptDeviceID, acceptKey,
		transactionID)

	sasBytes, err := sas.GenerateBytes([]byte(sasInfo), 5)
	if err != nil {
		return [3]uint{0, 0, 0}, err
	}

	numbers := [3]uint{
		(uint(sasBytes[0])<<5 | uint(sasBytes[1])>>3) + 1000,
		(uint(sasBytes[1]&0x7)<<10 | uint(sasBytes[2])<<2 | uint(sasBytes[3]>>6)) + 1000,
		(uint(sasBytes[3]&0x3F)<<7 | uint(sasBytes[4])>>1) + 1000,
	}
	mach.Log.Debug("Generated SAS numbers are: %v-%v-%v", numbers[0], numbers[1], numbers[2])

	return numbers, nil
}

// GetSASVerificationEmojis generates the three numbers that need to match with the other device for a verification to be valid.
func (mach *OlmMachine) GetSASVerificationEmojis(initUserID id.UserID, initDeviceID id.DeviceID, initKey string,
	acceptUserID id.UserID, acceptDeviceID id.DeviceID, acceptKey string,
	transactionID string, sas *olm.SAS) ([7]VerificationEmoji, error) {

	sasInfo := fmt.Sprintf("MATRIX_KEY_VERIFICATION_SAS|%s|%s|%s|%s|%s|%s|%s",
		initUserID, initDeviceID, initKey,
		acceptUserID, acceptDeviceID, acceptKey,
		transactionID)

	var emojis [7]VerificationEmoji
	sasBytes, err := sas.GenerateBytes([]byte(sasInfo), 6)
	emojisStr := ""

	if err != nil {
		return emojis, err
	}

	sasNum := uint64(sasBytes[0])<<40 | uint64(sasBytes[1])<<32 | uint64(sasBytes[2])<<24 |
		uint64(sasBytes[3])<<16 | uint64(sasBytes[4])<<8 | uint64(sasBytes[5])

	for i := 0; i < len(emojis); i++ {
		// take nth group of 6 bits
		emojiIdx := (sasNum >> (48 - (i+1)*6)) & 0x3F
		emoji := allEmojis[emojiIdx]
		emojis[i] = emoji
		emojisStr += fmt.Sprintf("%c (%v) ", emoji.Emoji, emoji.Description)
	}

	mach.Log.Debug("Generated SAS numbers are: %v", emojisStr)

	return emojis, nil
}
