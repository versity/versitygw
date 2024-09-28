// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package controllers

import (
	"github.com/versity/versitygw/auth"
	"sync"
)

// Ensure, that IAMServiceMock does implement auth.IAMService.
// If this is not the case, regenerate this file with moq.
var _ auth.IAMService = &IAMServiceMock{}

// IAMServiceMock is a mock implementation of auth.IAMService.
//
//	func TestSomethingThatUsesIAMService(t *testing.T) {
//
//		// make and configure a mocked auth.IAMService
//		mockedIAMService := &IAMServiceMock{
//			CreateAccountFunc: func(account auth.Account) error {
//				panic("mock out the CreateAccount method")
//			},
//			DeleteUserAccountFunc: func(access string) error {
//				panic("mock out the DeleteUserAccount method")
//			},
//			GetUserAccountFunc: func(access string) (auth.Account, error) {
//				panic("mock out the GetUserAccount method")
//			},
//			ListUserAccountsFunc: func() ([]auth.Account, error) {
//				panic("mock out the ListUserAccounts method")
//			},
//			ShutdownFunc: func() error {
//				panic("mock out the Shutdown method")
//			},
//			UpdateUserAccountFunc: func(access string, props auth.MutableProps) error {
//				panic("mock out the UpdateUserAccount method")
//			},
//		}
//
//		// use mockedIAMService in code that requires auth.IAMService
//		// and then make assertions.
//
//	}
type IAMServiceMock struct {
	// CreateAccountFunc mocks the CreateAccount method.
	CreateAccountFunc func(account auth.Account) error

	// DeleteUserAccountFunc mocks the DeleteUserAccount method.
	DeleteUserAccountFunc func(access string) error

	// GetUserAccountFunc mocks the GetUserAccount method.
	GetUserAccountFunc func(access string) (auth.Account, error)

	// ListUserAccountsFunc mocks the ListUserAccounts method.
	ListUserAccountsFunc func() ([]auth.Account, error)

	// ShutdownFunc mocks the Shutdown method.
	ShutdownFunc func() error

	// UpdateUserAccountFunc mocks the UpdateUserAccount method.
	UpdateUserAccountFunc func(access string, props auth.MutableProps) error

	// calls tracks calls to the methods.
	calls struct {
		// CreateAccount holds details about calls to the CreateAccount method.
		CreateAccount []struct {
			// Account is the account argument value.
			Account auth.Account
		}
		// DeleteUserAccount holds details about calls to the DeleteUserAccount method.
		DeleteUserAccount []struct {
			// Access is the access argument value.
			Access string
		}
		// GetUserAccount holds details about calls to the GetUserAccount method.
		GetUserAccount []struct {
			// Access is the access argument value.
			Access string
		}
		// ListUserAccounts holds details about calls to the ListUserAccounts method.
		ListUserAccounts []struct {
		}
		// Shutdown holds details about calls to the Shutdown method.
		Shutdown []struct {
		}
		// UpdateUserAccount holds details about calls to the UpdateUserAccount method.
		UpdateUserAccount []struct {
			Props  auth.MutableProps
			Access string
		}
	}
	lockCreateAccount     sync.RWMutex
	lockDeleteUserAccount sync.RWMutex
	lockGetUserAccount    sync.RWMutex
	lockListUserAccounts  sync.RWMutex
	lockShutdown          sync.RWMutex
	lockUpdateUserAccount sync.RWMutex
}

// CreateAccount calls CreateAccountFunc.
func (mock *IAMServiceMock) CreateAccount(account auth.Account) error {
	if mock.CreateAccountFunc == nil {
		panic("IAMServiceMock.CreateAccountFunc: method is nil but IAMService.CreateAccount was just called")
	}
	callInfo := struct {
		Account auth.Account
	}{
		Account: account,
	}
	mock.lockCreateAccount.Lock()
	mock.calls.CreateAccount = append(mock.calls.CreateAccount, callInfo)
	mock.lockCreateAccount.Unlock()
	return mock.CreateAccountFunc(account)
}

// CreateAccountCalls gets all the calls that were made to CreateAccount.
// Check the length with:
//
//	len(mockedIAMService.CreateAccountCalls())
func (mock *IAMServiceMock) CreateAccountCalls() []struct {
	Account auth.Account
} {
	var calls []struct {
		Account auth.Account
	}
	mock.lockCreateAccount.RLock()
	calls = mock.calls.CreateAccount
	mock.lockCreateAccount.RUnlock()
	return calls
}

// DeleteUserAccount calls DeleteUserAccountFunc.
func (mock *IAMServiceMock) DeleteUserAccount(access string) error {
	if mock.DeleteUserAccountFunc == nil {
		panic("IAMServiceMock.DeleteUserAccountFunc: method is nil but IAMService.DeleteUserAccount was just called")
	}
	callInfo := struct {
		Access string
	}{
		Access: access,
	}
	mock.lockDeleteUserAccount.Lock()
	mock.calls.DeleteUserAccount = append(mock.calls.DeleteUserAccount, callInfo)
	mock.lockDeleteUserAccount.Unlock()
	return mock.DeleteUserAccountFunc(access)
}

// DeleteUserAccountCalls gets all the calls that were made to DeleteUserAccount.
// Check the length with:
//
//	len(mockedIAMService.DeleteUserAccountCalls())
func (mock *IAMServiceMock) DeleteUserAccountCalls() []struct {
	Access string
} {
	var calls []struct {
		Access string
	}
	mock.lockDeleteUserAccount.RLock()
	calls = mock.calls.DeleteUserAccount
	mock.lockDeleteUserAccount.RUnlock()
	return calls
}

// GetUserAccount calls GetUserAccountFunc.
func (mock *IAMServiceMock) GetUserAccount(access string) (auth.Account, error) {
	if mock.GetUserAccountFunc == nil {
		panic("IAMServiceMock.GetUserAccountFunc: method is nil but IAMService.GetUserAccount was just called")
	}
	callInfo := struct {
		Access string
	}{
		Access: access,
	}
	mock.lockGetUserAccount.Lock()
	mock.calls.GetUserAccount = append(mock.calls.GetUserAccount, callInfo)
	mock.lockGetUserAccount.Unlock()
	return mock.GetUserAccountFunc(access)
}

// GetUserAccountCalls gets all the calls that were made to GetUserAccount.
// Check the length with:
//
//	len(mockedIAMService.GetUserAccountCalls())
func (mock *IAMServiceMock) GetUserAccountCalls() []struct {
	Access string
} {
	var calls []struct {
		Access string
	}
	mock.lockGetUserAccount.RLock()
	calls = mock.calls.GetUserAccount
	mock.lockGetUserAccount.RUnlock()
	return calls
}

// ListUserAccounts calls ListUserAccountsFunc.
func (mock *IAMServiceMock) ListUserAccounts() ([]auth.Account, error) {
	if mock.ListUserAccountsFunc == nil {
		panic("IAMServiceMock.ListUserAccountsFunc: method is nil but IAMService.ListUserAccounts was just called")
	}
	callInfo := struct {
	}{}
	mock.lockListUserAccounts.Lock()
	mock.calls.ListUserAccounts = append(mock.calls.ListUserAccounts, callInfo)
	mock.lockListUserAccounts.Unlock()
	return mock.ListUserAccountsFunc()
}

// ListUserAccountsCalls gets all the calls that were made to ListUserAccounts.
// Check the length with:
//
//	len(mockedIAMService.ListUserAccountsCalls())
func (mock *IAMServiceMock) ListUserAccountsCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockListUserAccounts.RLock()
	calls = mock.calls.ListUserAccounts
	mock.lockListUserAccounts.RUnlock()
	return calls
}

// Shutdown calls ShutdownFunc.
func (mock *IAMServiceMock) Shutdown() error {
	if mock.ShutdownFunc == nil {
		panic("IAMServiceMock.ShutdownFunc: method is nil but IAMService.Shutdown was just called")
	}
	callInfo := struct {
	}{}
	mock.lockShutdown.Lock()
	mock.calls.Shutdown = append(mock.calls.Shutdown, callInfo)
	mock.lockShutdown.Unlock()
	return mock.ShutdownFunc()
}

// ShutdownCalls gets all the calls that were made to Shutdown.
// Check the length with:
//
//	len(mockedIAMService.ShutdownCalls())
func (mock *IAMServiceMock) ShutdownCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockShutdown.RLock()
	calls = mock.calls.Shutdown
	mock.lockShutdown.RUnlock()
	return calls
}

// UpdateUserAccount calls UpdateUserAccountFunc.
func (mock *IAMServiceMock) UpdateUserAccount(access string, props auth.MutableProps) error {
	if mock.UpdateUserAccountFunc == nil {
		panic("IAMServiceMock.UpdateUserAccountFunc: method is nil but IAMService.UpdateUserAccount was just called")
	}
	callInfo := struct {
		Props  auth.MutableProps
		Access string
	}{
		Access: access,
		Props:  props,
	}
	mock.lockUpdateUserAccount.Lock()
	mock.calls.UpdateUserAccount = append(mock.calls.UpdateUserAccount, callInfo)
	mock.lockUpdateUserAccount.Unlock()
	return mock.UpdateUserAccountFunc(access, props)
}

// UpdateUserAccountCalls gets all the calls that were made to UpdateUserAccount.
// Check the length with:
//
//	len(mockedIAMService.UpdateUserAccountCalls())
func (mock *IAMServiceMock) UpdateUserAccountCalls() []struct {
	Props  auth.MutableProps
	Access string
} {
	var calls []struct {
		Props  auth.MutableProps
		Access string
	}
	mock.lockUpdateUserAccount.RLock()
	calls = mock.calls.UpdateUserAccount
	mock.lockUpdateUserAccount.RUnlock()
	return calls
}
