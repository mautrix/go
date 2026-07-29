package bridgev2

import (
	"context"
	"testing"
)

func TestPortalBackgroundContextUsesPortalLifetime(t *testing.T) {
	operationCtx, cancelOperation := context.WithCancel(context.Background())
	portalCtx, cancelPortal := context.WithCancel(context.Background())
	portal := &Portal{backgroundCtx: portalCtx}
	ctx := portal.backgroundContext(operationCtx)

	cancelOperation()
	if ctx.Err() != nil {
		t.Fatalf("operation cancellation reached portal context: %v", ctx.Err())
	}
	cancelPortal()
	if ctx.Err() != context.Canceled {
		t.Fatalf("portal cancellation did not reach portal context: %v", ctx.Err())
	}
}
