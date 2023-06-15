// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/jayanthvn/pure-gobpf/pkg/ebpf_progs (interfaces: BpfProgAPIs)

// Package mock_ebpf_progs is a generated GoMock package.
package mock_ebpf_progs

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	ebpf_progs "github.com/jayanthvn/pure-gobpf/pkg/ebpf_progs"
)

// MockBpfProgAPIs is a mock of BpfProgAPIs interface.
type MockBpfProgAPIs struct {
	ctrl     *gomock.Controller
	recorder *MockBpfProgAPIsMockRecorder
}

// MockBpfProgAPIsMockRecorder is the mock recorder for MockBpfProgAPIs.
type MockBpfProgAPIsMockRecorder struct {
	mock *MockBpfProgAPIs
}

// NewMockBpfProgAPIs creates a new mock instance.
func NewMockBpfProgAPIs(ctrl *gomock.Controller) *MockBpfProgAPIs {
	mock := &MockBpfProgAPIs{ctrl: ctrl}
	mock.recorder = &MockBpfProgAPIsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBpfProgAPIs) EXPECT() *MockBpfProgAPIsMockRecorder {
	return m.recorder
}

// BpfGetProgFromPinPath mocks base method.
func (m *MockBpfProgAPIs) BpfGetProgFromPinPath(arg0 string) (ebpf_progs.BpfProgInfo, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BpfGetProgFromPinPath", arg0)
	ret0, _ := ret[0].(ebpf_progs.BpfProgInfo)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// BpfGetProgFromPinPath indicates an expected call of BpfGetProgFromPinPath.
func (mr *MockBpfProgAPIsMockRecorder) BpfGetProgFromPinPath(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BpfGetProgFromPinPath", reflect.TypeOf((*MockBpfProgAPIs)(nil).BpfGetProgFromPinPath), arg0)
}

// GetBPFProgAssociatedMapsIDs mocks base method.
func (m *MockBpfProgAPIs) GetBPFProgAssociatedMapsIDs(arg0 int) ([]uint32, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBPFProgAssociatedMapsIDs", arg0)
	ret0, _ := ret[0].([]uint32)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBPFProgAssociatedMapsIDs indicates an expected call of GetBPFProgAssociatedMapsIDs.
func (mr *MockBpfProgAPIsMockRecorder) GetBPFProgAssociatedMapsIDs(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBPFProgAssociatedMapsIDs", reflect.TypeOf((*MockBpfProgAPIs)(nil).GetBPFProgAssociatedMapsIDs), arg0)
}

// LoadProg mocks base method.
func (m *MockBpfProgAPIs) LoadProg(arg0 string, arg1 []byte, arg2, arg3 string, arg4 int) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LoadProg", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LoadProg indicates an expected call of LoadProg.
func (mr *MockBpfProgAPIsMockRecorder) LoadProg(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadProg", reflect.TypeOf((*MockBpfProgAPIs)(nil).LoadProg), arg0, arg1, arg2, arg3, arg4)
}

// PinProg mocks base method.
func (m *MockBpfProgAPIs) PinProg(arg0 uint32, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PinProg", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// PinProg indicates an expected call of PinProg.
func (mr *MockBpfProgAPIsMockRecorder) PinProg(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PinProg", reflect.TypeOf((*MockBpfProgAPIs)(nil).PinProg), arg0, arg1)
}

// UnPinProg mocks base method.
func (m *MockBpfProgAPIs) UnPinProg(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnPinProg", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UnPinProg indicates an expected call of UnPinProg.
func (mr *MockBpfProgAPIsMockRecorder) UnPinProg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnPinProg", reflect.TypeOf((*MockBpfProgAPIs)(nil).UnPinProg), arg0)
}
