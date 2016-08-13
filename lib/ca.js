'use strict'

const pem = require('pem')
const os = require('os')
const path = require('path')
const fs = require('fs')

class CA {
  constructor (config) {
    config = config || {}

    Object.defineProperties(this, {
      config: {
        enumerable: false,
        writable: false,
        configurable: false,
        value: config
      },

      name: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: path.basename(process.cwd())
      },

      days: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: config.days || 3650
      },

      bitsize: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: config.keysize || 2048
      },

      clientkey : {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      hash: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: config.hash || 'sha256'
      },

      country: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: '??'
      },

      state: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: 'UNKNOWN'
      },

      city: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: 'UNKNOWN'
      },

      organization: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: os.hostname()
      },

      organizationUnit: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: process.env.USER
      },

      commonName: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: os.hostname()
      },

      altNames: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: ['localhost', '127.0.0.1']
      },

      cipher: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: config.cipher || 'aes256'
      },

      email: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      password: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      encryptKey: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: config.encryptKey || null
      },

      privateKey: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      CSR: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      cacert: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      cakey: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      cacertfilename: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      },

      cert: {
        enumerable: false,
        writable: true,
        configurable: false,
        value: null
      }
    })
  }

  reset (all = false) {
    this.days = this.config.days || 3650
    this.bitsize = this.config.keysize || 2048
    this.clientkey = null
    this.hash = this.config.hash || 'sha256'
    this.organization = os.hostname()
    this.organizationUnit = process.env.USER
    this.commonName = os.hostname()
    this.altNames = ['localhost', '127.0.0.1']
    this.cipher = this.config.cipher || 'aes256'
    this.email = null
    this.password = null
    this.encryptKey = this.config.encryptKey || null
    this.privateKey = null
    this.CSR = null

    if (all) {
      this.country = '??'
      this.state = 'UNKNOWN'
      this.city = 'UNKNOWN'
      this.cacert = null
      this.cakey = null
      this.cacertfilename = null
      this.cert = null
    }
  }

  createPrivateKey (callback) {
    let opts = {
      cipher: this.cipher
    }

    if (this.encryptkey) {
      opts.password = this.encryptKey
    }

    pem.createPrivateKey(this.bitsize, opts, (err, data) => {
      this.privateKey = data.key

      fs.writeFileSync(path.join(process.cwd(), this.name + '.key'), this.privateKey)

      callback(this.privateKey)
    })
  }

  createCSR (filename, callback) {
    if (typeof filename === 'function') {
      callback = filename
      filename = false
    }

    let options = {
      clientKey: this.clientKey,
      keyBitSize: this.keyBitSize,
      country: this.country,
      state: this.state,
      locality: this.locality,
      organization: this.organization,
      organizationUnit: this.organizationUnit,
      commonName: this.commonName,
      altNames: this.altNames
    }

    if (this.encryptKey) {
      options.clientKeyPassword = this.encryptKey
    }

    if (this.email) {
      csroptions.emailAddress = this.email
    }

    pem.createCSR(options, (err, data) => {
      this.CSR = data.csr

      if (filename) {
        fs.writeFileSync(filename === true ? path.join(process.cwd(), this.name + '.csr') : filename, this.CSR)
      }

      callback(this.CSR)
    })
  }

  createCaCertificate (callback) {
    let options = {
      selfSigned: true,
      days: this.days + 365,
      serial: Date.now()
    }

    pem.createCertificate(options, (err, data) => {
      this.cacertfilename = path.join(process.cwd(), this.name + '.ca.pem')
      this.cacert = data.certificate
      this.cakey = data.clientKey

      fs.writeFileSync(this.cacertfilename, this.cacert)
      fs.writeFileSync(path.join(process.cwd(), this.name + '.ca.key'), this.cakey)

      callback(data.certificate)
    })
  }

  createCertificate (filename, callback) {
    if (typeof filename === 'function') {
      callback = filename
      filename = false
    }

    let options = {
      selfSigned: this.cacert === null,
      days: this.days,
      serial: Date.now()
    }

    if (this.cacert !== null) {
      options.serviceCertificate = this.cacert
      options.serviceKey = this.cakey
      if (this.cacertfilename !== null) {
        options.certFiles = [this.cacertfilename]
      }

      options.country = this.country
      options.state = this.state
      options.locality = this.city
      options.organization = this.organization
      options.organizationUnit = this.organizationUnit
      options.commonName = this.commonName
    } else if (this.CSR !== null) {
      options.csr = this.CSR
    }

    pem.createCertificate(options, (err, cert) => {
      fs.writeFileSync(filename === true ? path.join(process.cwd(), this.name + '.pem') : filename, cert.certificate)

      if (cert.clientKey) {
        this.privateKey = cert.clientKey
        fs.writeFileSync(filename === true ? path.join(process.cwd(), this.name + '.key') : filename, cert.clientKey)
      }

      this.cert = cert.certificate

      callback(cert.certificate)
    })
  }

  createPublicKey (certificate, filename, callback) {
    if (typeof filename === 'function') {
      callback = filename
      filename = false
    }

    pem.getPublicKey(certificate, (err, data) => {
      if (filename) {
        fs.writeFileSync(filename === true ? path.join(process.cwd(), this.name + '_rsa.pub') : filename, data.publicKey)
      }

      callback(data.publicKey)
    })
  }

  createPKCS12Store (callback) {
    let options = {
      cipher: this.cipher
    }

    if (this.encryptKey) {
      options.clientKeyPassword = this.encryptKey
    }

    if (this.cacertfilename) {
      options.certFiles = [this.cacertfilename]
    }

    const pwd = this.encryptKey || 'nopassword'
    pem.createPkcs12(this.privateKey, this.cert, pwd, options, (err, pfx) => {
      fs.writeFileSync(path.join(process.cwd(), this.name + '.pfx'), pfx.pkcs12, 'binary')
      console.warn('  --> PFX Password:', pwd === 'nopassword' ? pwd : (pwd.replace(/\B[a-z0-9\w]/gi, '*')))
      callback()
    })
  }
}

module.exports = CA
