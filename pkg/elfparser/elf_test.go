package elfparser

import (
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	mock_ebpf_maps "github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps/mocks"
	mock_ebpf_progs "github.com/jayanthvn/pure-gobpf/pkg/ebpf_progs/mocks"
	"github.com/stretchr/testify/assert"
)

type testMocks struct {
	path       string
	ctrl       *gomock.Controller
	ebpf_progs *mock_ebpf_progs.MockBpfProgAPIs
	ebpf_maps  *mock_ebpf_maps.MockBpfMapAPIs
}

func setup(t *testing.T) *testMocks {
	ctrl := gomock.NewController(t)
	return &testMocks{
		path:       "FILENAME",
		ctrl:       ctrl,
		ebpf_progs: mock_ebpf_progs.NewMockBpfProgAPIs(ctrl),
		ebpf_maps:  mock_ebpf_maps.NewMockBpfMapAPIs(ctrl),
	}
}

func TestLoadelf(t *testing.T) {
	m := setup(t)
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()
	ctrl := gomock.NewController(t)
	mockAPIs := mock_ebpf_maps.NewMockBpfMapAPIs(ctrl)
	mockProgAPIs := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)

	mockAPIs.EXPECT().CreateMap(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().LoadProg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockAPIs.EXPECT().PinMap(gomock.Any()).AnyTimes()
	err := doLoadELF(f, mockAPIs, mockProgAPIs, "test")
	assert.NoError(t, err)
}
