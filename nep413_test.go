package nep413_test

import (
	"testing"

	"github.com/brennanjl/nep413"
)

func Test_Nep413(t *testing.T) {
	msg := nep413.Nep413Message{
		Message:   "idOS authentication",
		Recipient: "idos.network",
		Nonce:     [32]byte{5, 233, 107, 175, 203, 182, 15, 111, 97, 146, 18, 10, 118, 80, 180, 9, 186, 39, 255, 93, 36, 218, 196, 25, 72, 177, 237, 28, 173, 75, 17, 31},
	}

	res := nep413.Nep413SignatureResponse{
		Signature: "Ni+rXvOtyzRr7X+qtvQ9+iJUu2e8L/e6cPjSzOYr+6W22chVnptTW0QqTUhFgKUbgPwd2tTcfB1D9Q+0Xb+sBg==",
		PublicKey: "ed25519:8HnzkUaX21h99idPghFajoV3JZvy3SmJ4mqVwSVfLByg",
	}

	// sign the message
	err := nep413.Verify(&msg, &res)
	if err != nil {
		t.Fatal(err)
	}
}
