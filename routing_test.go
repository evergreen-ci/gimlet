package gimlet

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type RoutingSuite struct {
	require *require.Assertions
	suite.Suite
}

func TestRoutingSuite(t *testing.T) {
	suite.Run(t, new(RoutingSuite))
}

func (s *RoutingSuite) SetupSuite() {
	s.require = s.Require()
}

func (s *RoutingSuite) TestRouteConstructor() {
	s.True(true)
}
