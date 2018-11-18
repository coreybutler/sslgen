#!/usr/bin/env node

const inquirer = require('inquirer')
const pem = require('pem')
const http = require('http')
const path = require('path')
const fs = require('fs')
const os = require('os')
const ShortBus = require('shortbus')
const CertificateAuthority = require('./lib/ca')
let csr = {}

http.get('http://ip-api.com/json', (res, x) => {
  let data = ''

  res.on('data', chunk => data += chunk.toString())

  res.on('end', () => {
    data = JSON.parse(data)
    csr = {
      country: data.countryCode,
      region: data.regionName,
      city: data.city
    }
    wizard()
  })

  res.resume()
}).on('error', (e) => {
  csr = {
    country: 'US',
    region: 'Unknown',
    city: 'Unknown'
  }
  wizard()
})

const wizard = () => {
  console.log('\n=========================\nLet\'s make a certificate!\n=========================\n')
  inquirer.prompt([{
    name: 'encryptkey',
    message: 'Do you want to encrypt the private key?',
    type: 'confirm',
    default: false
  }, {
    name: 'keysize',
    message: 'Private Key Size',
    type: 'list',
    choices: ['1024', '2048', '4096'],
    default: '2048',
    when: (answers) => {
      return answers.encryptkey
    }
  }, {
    name: 'cipher',
    message: 'Private Key Cipher',
    type: 'list',
    choices: [
      'aes128',
      'aes192',
      'aes256',
      'camellia128',
      'camellia192',
      'camellia256',
      'des',
      'des3',
      'idea'
    ],
    default: 'aes256',
    when: (answers) => {
      return answers.encryptkey
    }
  }, {
    name: 'pkpwd',
    message: 'Private Key Password (Optional)',
    type: 'password',
    when: (answers) => {
      return answers.encryptkey
    }
  }, {
    name: 'autocsr',
    message: 'Certificate Signing Request',
    type: 'list',
    choices: [
      {name: 'Autogenerate (Uses Common Values)', value: 'auto'},
      {name: 'Customize', value: 'custom'}
    ]
  }, {
    name: 'cn',
    message: 'Certificate Common Name',
    default: os.hostname(),
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'country',
    message: 'Country',
    default: csr.country,
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'state',
    message: 'State or Province',
    default: csr.region,
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'locality',
    message: 'City/Locality',
    default: csr.city,
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'org',
    message: 'Organization',
    default: os.hostname(),
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'ou',
    message: 'Organizational Unit',
    default: process.env.USER,
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'san',
    message: 'Subject Alternative Names (Comma Separated)',
    default: 'localhost, 127.0.0.1',
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'email',
    message: 'Email Address (NOT REQUIRED)',
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'hash',
    message: 'Encryption Type',
    type: 'list',
    choices: [
      'md5',
      'sha1',
      'sha256'
    ],
    default: 'sha256',
    when: (answers) => {
      return answers.autocsr === 'custom'
    }
  }, {
    name: 'other',
    message: 'Which additional files/formats do you want to create?',
    type: 'checkbox',
    choices: [
      {name: 'CA Certificate', value: 'ca', checked: false},
      {name: 'Public Key', value: 'pubkey', checked: false},
      {name: 'PKCS12 Store (.pfx)', value: 'pkcs12', checked: false},
      {name: 'Certificate Signing Request', value: 'csr', checked: false}
    ]
  }, {
    name: 'basename',
    message: "Base Filename",
    default: path.basename(process.cwd())
  }/*, {
    name: 'pfxpasswd',
    type: 'password',
    message: 'PKCS12 Password:',
    default: 'nopassword',
    when: function (answers) {
      if (answers.other.indexOf('pkcs12') >= 0) {
        return !answers.encryptkey
      }

      return false
    }
  }*/]).then((answers) => {
    // Configure Certificate Authority (Factory)
    let CA = new CertificateAuthority({
      keysize: parseInt(answers.keysize || '2048', 10),
      encryptKey: answers.encryptkey ? answers.pkpwd : null,
      cipher: answers.cipher || 'aes256',
      hash: answers.hash
    })

    CA.country = answers.country || csr.country
    CA.state = answers.state || csr.region
    CA.locality = answers.city || csr.city
    CA.organization = answers.org || os.hostname()
    CA.organizationUnit = answers.ou || process.env.USER
    CA.commonName = answers.cn || CA.name
    CA.altNames = answers.hasOwnProperty('san') ? answers.san.split(',') : ['localhost', '127.0.0.1']

    if (answers.email) {
      CA.email = answers.email
    }

    CA.name = answers.basename || CA.name

    // Setup Tasks
    let tasks = new ShortBus()

    // If a CA is requested, support it
    if (answers.other.indexOf('ca') >= 0) {
      tasks.add('Generate CA certificate.', function (done) {
        CA.createCaCertificate(done)
      })
    }

    // Generate the private key
    tasks.add('Generating Private Key.', function (done) {
      CA.createPrivateKey(done)
    })

    // Generate a CSR
    if (answers.other.indexOf('csr') >= 0) {
      tasks.add('Generating Certificate Signing Request.', function (done) {
        CA.createCSR(answers.other.indexOf('csr') < 0, done)
      })
    }

    // // Make the primary certificate.
    tasks.add('Generate certificate.', function (done) {
      CA.createCertificate(true, done)
    })

    // If public key is requested, write it.
    if (answers.other.indexOf('pubkey') >= 0) {
      tasks.add('Generate public key.', function (done) {
        CA.createPublicKey(CA.cert, true, done)
      })
    }

    // // If a PKCS12 Store is requested, make it.
    if (answers.other.indexOf('pkcs12') >= 0) {
      tasks.add('Generate PKCS12 Store.', function (done) {
        CA.createPKCS12Store(done)
      })
    }

    // When everything is done, notify the user.
    tasks.on('complete', function () {
      console.log('Done')
    })

    // Run
    tasks.process(true)
  })
}
