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
	ebpf_progs *mock_ebpf_progs.MockAPIs
	ebpf_maps  *mock_ebpf_maps.MockAPIs
}

func setup(t *testing.T) *testMocks {
	ctrl := gomock.NewController(t)
	return &testMocks{
		path:       "../../test/xdp_prog/xdp_fw.elf",
		ctrl:       ctrl,
		ebpf_progs: mock_ebpf_progs.NewMockAPIs(ctrl),
		ebpf_maps:  mock_ebpf_maps.NewMockAPIs(ctrl),
	}
}

func TestLoadelf(t *testing.T) {
	m := setup(t)
	defer m.ctrl.Finish()
	mockContext := &BPFParser{
		bpfMapAPIs:  m.ebpf_maps,
		bpfProgAPIs: m.ebpf_progs,
	}
	f, _ := os.Open(m.path)
	defer f.Close()

	m.ebpf_maps.EXPECT().CreateMap(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().LoadProg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	err := mockContext.doLoadELF(f)
	assert.NoError(t, err)
}
