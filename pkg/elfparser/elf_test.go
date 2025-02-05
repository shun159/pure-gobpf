// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

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

func setup(t *testing.T, testPath string) *testMocks {
	ctrl := gomock.NewController(t)
	return &testMocks{
		path:       testPath,
		ctrl:       ctrl,
		ebpf_progs: mock_ebpf_progs.NewMockBpfProgAPIs(ctrl),
		ebpf_maps:  mock_ebpf_maps.NewMockBpfMapAPIs(ctrl),
	}
}

func TestLoadelf(t *testing.T) {
	m := setup(t, "../../test-data/tc.ingress.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	ctrl := gomock.NewController(t)
	mockAPIs := mock_ebpf_maps.NewMockBpfMapAPIs(ctrl)
	mockProgAPIs := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)

	mockAPIs.EXPECT().CreateMap(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().LoadProg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockAPIs.EXPECT().PinMap(gomock.Any()).AnyTimes()
	mockAPIs.EXPECT().BpfGetMapFromPinPath(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().BpfGetProgFromPinPath(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	_, _, err := doLoadELF(f, mockAPIs, mockProgAPIs, "test")
	assert.NoError(t, err)
}

func TestLoadelfWithoutReloc(t *testing.T) {
	m := setup(t, "../../test-data/tc.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	ctrl := gomock.NewController(t)
	mockAPIs := mock_ebpf_maps.NewMockBpfMapAPIs(ctrl)
	mockProgAPIs := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)

	mockAPIs.EXPECT().CreateMap(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().LoadProg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockAPIs.EXPECT().PinMap(gomock.Any()).AnyTimes()
	mockAPIs.EXPECT().BpfGetMapFromPinPath(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().BpfGetProgFromPinPath(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	_, _, err := doLoadELF(f, mockAPIs, mockProgAPIs, "test")
	assert.NoError(t, err)
}

func TestLoadelfWithoutProg(t *testing.T) {
	m := setup(t, "../../test-data/test.map.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	ctrl := gomock.NewController(t)
	mockAPIs := mock_ebpf_maps.NewMockBpfMapAPIs(ctrl)
	mockProgAPIs := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)

	mockAPIs.EXPECT().CreateMap(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().LoadProg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockAPIs.EXPECT().PinMap(gomock.Any()).AnyTimes()
	mockAPIs.EXPECT().BpfGetMapFromPinPath(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().BpfGetProgFromPinPath(gomock.Any()).AnyTimes()
	mockProgAPIs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	_, _, err := doLoadELF(f, mockAPIs, mockProgAPIs, "test")
	assert.NoError(t, err)
}
