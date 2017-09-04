// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This code is based on the example in https://github.com/kelseyhightower/kube-cert-manager/blob/master/tls-app/certificate-manager.go

package certutils

import (
	"crypto/tls"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// CertReloader provides a mechanism for reloading a TLS key and cert upon file change
type CertReloader struct {
	sync.RWMutex
	certificate *tls.Certificate
	certFile    string
	keyFile     string
	Error       chan error
	watcher     *fsnotify.Watcher
}

// NewCertReloader returns a new CertReloader
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	cr := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
		Error:    make(chan error, 10),
	}
	err := cr.setCertificate()
	if err != nil {
		return nil, err
	}

	go cr.watchCertificate()

	return cr, nil
}

// GetCertificate implements the tls.Config GetCertificate() func
func (cr *CertReloader) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.RLock()
	defer cr.RUnlock()
	return cr.certificate, nil
}

// GetCertificate implements the tls.Config GetClientCertificate() func
func (cr *CertReloader) GetClientCertificate(req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cr.RLock()
	defer cr.RUnlock()
	return cr.certificate, nil
}

// TLSConfigApplyReloader patches a *tls.Config struct by setting the GetCertificate and GetClientCertificate
// methods.
func (cr *CertReloader) TLSConfigApplyReloader(cfg *tls.Config) {
	cfg.GetCertificate = cr.GetCertificate
	cfg.GetClientCertificate = cr.GetClientCertificate
}

func (cr *CertReloader) setCertificate() error {
	c, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return err
	}
	cr.Lock()
	cr.certificate = &c
	cr.Unlock()
	return nil
}

func (cr *CertReloader) watchCertificate() error {
	err := cr.newWatcher()
	if err != nil {
		return err
	}

	for {
		select {
		case <-cr.watcher.Events:
			err := cr.setCertificate()
			if err != nil {
				cr.Error <- err
			}
			err = cr.resetWatcher()
			if err != nil {
				cr.Error <- err
			}
		case err := <-cr.watcher.Errors:
			cr.Error <- err
		}
	}
}

func (cr *CertReloader) newWatcher() error {
	var err error
	cr.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	err = cr.watcher.Add(cr.certFile)
	if err != nil {
		return err
	}
	return cr.watcher.Add(cr.keyFile)
}

func (cr *CertReloader) resetWatcher() error {
	err := cr.watcher.Close()
	if err != nil {
		return err
	}
	return cr.newWatcher()
}
