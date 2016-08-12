#!/usr/bin/env node

const inquirer = require('inquirer')
const pem = require('pem')
const http = require('http')
const path = require('path')
const fs = require('fs')
const os = require('os')
let csr = {}

http.get('http://ip-api.com/json', (res, x) => {
  let data = ''
  res.on('data', (chunk) => {
    data += chunk.toString()
  })
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
      {name: 'Public Key', value: 'pubkey', checked: true},
      {name: 'PKCS12 Store (.pfx)', value: 'pkcs12', checked: false},
      {name: 'Certificate Signing Request', value: 'csr', checked: false}
    ]
  }, {
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
  }]).then((answers) => {
    let crtname = path.basename(process.cwd())

    // Generate a private key
    answers.keysize = parseInt(answers.keysize || '2048', 10)

    let options = {}

    if (answers.encryptkey) {
      options.cipher = answers.cipher
      options.password = answers.pkpwd
    }

    pem.createPrivateKey(answers.keysize, options, (err, pkdata) => {
      fs.writeFileSync(path.join(process.cwd(), crtname + '.key'), pkdata.key)

      // Generate a CSR
      let csroptions = {
        clientKey: pkdata.key,
        keyBitsize: answers.keysize,
        hash: answers.hash || 'sha256',
        country: answers.country || csr.country,
        state: answers.state || csr.region,
        locality: answers.city || csr.city,
        organization: answers.org || os.hostname(),
        organizationUnit: answers.ou || process.env.USER,
        commonName: answers.cn || crtname,
        altNames: answers.hasOwnProperty('san') ? answers.san.split(',') : ['localhost', '127.0.0.1'],
      }

      if (answers.encryptkey) {
        csroptions.clientKeyPassword = answers.pkpwd
      }

      if (answers.email) {
        csroptions.emailAddress = answers.email
      }

      // Generate a CA Certificate if Requested
      if (answers.other.indexOf('ca') >= 0) {
        pem.createCertificate({
          selfSigned: true,
          days: 3650
        }, (err, cert, csr, clientKey, serviceKey) => {
          fs.writeFileSync(path.join(process.cwd(), crtname + '.ca.pem'), cert.certificate)
          // fs.writeFileSync(path.join(process.cwd(), crtname + '.ca.key'), cert.serviceKey)
          pem.createCertificate({
            serviceCertificate: cert.certificate,
            serviceKey: cert.serviceKey,
            serial: Date.now(),
            days: 365 * 11,
            country: csroptions.country,
            state: csroptions.state,
            locality: csroptions.locality,
            organization: csroptions.organization,
            organizationUnit: csroptions.organizationUnit,
            commonName: csroptions.commonName + ' CA'
        }, (err, keys) => {
            fs.writeFileSync(path.join(process.cwd(), crtname + '.key'), keys.clientKey)
            fs.writeFileSync(path.join(process.cwd(), crtname + '.pem'), keys.certificate)

            if (answers.other.indexOf('pubkey') >= 0) {
              pem.getPublicKey(keys.certificate, (err, pubkey) => {
                fs.writeFileSync(path.join(process.cwd(), crtname + '.pub'), pubkey.publicKey)
              })
            }

            if (answers.other.indexOf('csr') >= 0) {
              fs.writeFileSync(path.join(process.cwd(), crtname + '.csr'), keys.csr)
            }

            if (answers.other.indexOf('pkcs12') >= 0) {
              let p12Password = csroptions.clientKeyPassword || answers.pfxpasswd || 'nopassword'
              let opts = {}

              if (answers.cipher) {
                opts.cipher = answers.cipher
              }

              if (answers.clientKeyPassword) {
                opts.clientKeyPassword = answers.clientKeyPassword
              }

              opts.certFiles = [path.join(process.cwd(), crtname + '.ca.pem')]

              pem.createPkcs12(keys.clientKey, keys.certificate, p12Password, [options], (err, pfx) => {
                fs.writeFileSync(path.join(process.cwd(), crtname + '.pfx'), pfx.pkcs12, 'binary')
                console.warn('  >> PFX Password:', p12Password === 'nopassword' ? p12Password : (p12Password.replace(/\B[a-z0-9\w]/gi, '*')))
              })
            }
          })
        })
      } else {
        pem.createCertificate({
          selfSigned: true,
          serial: Date.now(),
          days: 365 * 10,
          country: csroptions.country,
          state: csroptions.state,
          locality: csroptions.locality,
          organization: csroptions.organization,
          organizationUnit: csroptions.organizationUnit,
          commonName: csroptions.commonName + ' CA'
        }, (err, keys) => {
          fs.writeFileSync(path.join(process.cwd(), crtname + '.key'), keys.clientKey)
          fs.writeFileSync(path.join(process.cwd(), crtname + '.pem'), keys.certificate)

          if (answers.other.indexOf('csr') >= 0) {
            fs.writeFileSync(path.join(process.cwd(), crtname + '.csr'), keys.csr)
          }

          if (answers.other.indexOf('pubkey') >= 0) {
            pem.getPublicKey(keys.certificate, (err, pubkey) => {
              fs.writeFileSync(path.join(process.cwd(), crtname + '.pub'), pubkey.publicKey)
            })
          }

          if (answers.other.indexOf('pkcs12') >= 0) {
            let p12Password = csroptions.clientKeyPassword || answers.pfxpasswd || 'nopassword'
            let opts = {}

            if (answers.cipher) {
              opts.cipher = answers.cipher
            }

            if (answers.clientKeyPassword) {
              opts.clientKeyPassword = answers.clientKeyPassword
            }

            pem.createPkcs12(keys.clientKey, keys.certificate, p12Password, [options], (err, pfx) => {
              fs.writeFileSync(path.join(process.cwd(), crtname + '.pfx'), pfx.pkcs12, 'binary')
              console.warn('  >> PFX Password:', p12Password === 'nopassword' ? p12Password : (p12Password.replace(/\B[a-z0-9\w]/gi, '*')))
            })
          }
        })
      }
    })
  })
}
