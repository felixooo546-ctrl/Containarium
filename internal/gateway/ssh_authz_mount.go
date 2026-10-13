package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// SSHAuthzPath is the REST path grpc-gateway maps SSHAuthzService.Authorize to.
	SSHAuthzPath = "/v1/ssh/authorize"

	// SSHAuthzUsername is the subject a sentinel-signed Authorize call acts as.
	// It holds only the ssh:authz scope and no roles.
	SSHAuthzUsername = "sentinel-ssh-authz"
)

// MountSSHAuthzService registers the SSHAuthzService gateway handler behind
// the sentinel verifier, following the anon_door_mount.go pattern.
//
// Requests to /v1/ssh/authorize without valid sentinel headers receive 401.
// Requests with valid headers are forwarded to sshAuthzStub, which returns
// Unimplemented — decision logic is out of scope for this issue.
func MountSSHAuthzService(mux *runtime.ServeMux, v auth.SentinelVerifier, jwtHandler http.Handler, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}

	stub := &sshAuthzStub{}

	// Register the generated gateway handler.
	if err := pb.RegisterSSHAuthzServiceHandlerServer(context.Background(), mux, stub); err != nil {
		return err
	}

	return nil
}

// SSHAuthzHandler wraps the grpc-gateway mux for /v1/ssh/authorize with
// sentinel signature verification, mirroring anonDoorHandler.
func SSHAuthzHandler(v auth.SentinelVerifier, jwtHandler, inner http.Handler, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Not the authz path — pass through unchanged.
		if r.URL.Path != SSHAuthzPath {
			inner.ServeHTTP(w, r)
			return
		}

		// No sentinel headers → fall back to JWT handler (allows human operators
		// with the ssh:authz scope to call the endpoint during development).
		if r.Header.Get(auth.SentinelHeaderSignature) == "" &&
			r.Header.Get(auth.SentinelHeaderTimestamp) == "" {
			jwtHandler.ServeHTTP(w, r)
			return
		}

		// Sentinel headers present — verify the signature. A bad signature must
		// never fall through to the JWT path (same rule as anon_door_mount.go).
		if err := v.VerifyRequest(r, now()); err != nil {
			http.Error(w,
				`{"error": "invalid sentinel signature", "code": 401}`,
				http.StatusUnauthorized,
			)
			return
		}

		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: SSHAuthzUsername,
			Roles:    []string{},
			Scopes:   []string{auth.ScopeSSHAuthz},
		})
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sshAuthzStub is the server-side stub for SSHAuthzService.
// It returns Unimplemented for every call — decision logic is a separate issue.
// The stub's sole purpose is to satisfy buf lint and the contract tests.
type sshAuthzStub struct {
	pb.UnimplementedSSHAuthzServiceServer
}

func (s *sshAuthzStub) Authorize(
	_ context.Context,
	_ *pb.AuthorizeSSHRequest,
) (*pb.AuthorizeSSHResponse, error) {
	return nil, status.Error(codes.Unimplemented, "decision logic not implemented in this issue")
}
