/* Copyright (c) 1996-2016, OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using System;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Tpm2Lib;

namespace Opc.Ua
{
    /// <summary>
    /// Provides access to a simple file based certificate store.
    /// </summary>
    public class TPMCertificateStore : ICertificateStore
    {
        public TPMCertificateStore()
        {
            m_certificates = new Dictionary<string, X509Certificate2>();
        }
        
        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                Close();
            }
        }
        
        public void Open(string location)
        {
            lock (m_lock)
            {
                m_tpmDevice.Connect();
                m_tpm = new Tpm2(m_tpmDevice);
            }
        }

        public void Close()
        {
            lock (m_lock)
            {
                m_tpm.Dispose();
                m_certificates.Clear();
            }
        }

        public Task<X509Certificate2Collection> Enumerate()
        {
            lock (m_lock)
            {
                IDictionary<string, X509Certificate2> certificatesInStore = Load(null);

                X509Certificate2Collection certificates = new X509Certificate2Collection();
                foreach (X509Certificate2 entry in certificatesInStore.Values)
                {
                    certificates.Add(entry);
                }

                return Task.FromResult(certificates);
            }
        }

        public Task Add(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException("certificate");
         
            lock (m_lock)
            {
                byte[] data = null;

                // check for existing certificate
                X509Certificate2 entry = Find(certificate.Thumbprint);

                if (entry != null)
                {
                    throw new ArgumentException("A certificate with the same thumbprint is already in the store.");
                }

                if (certificate.HasPrivateKey)
                {
                    data = certificate.Export(X509ContentType.Pkcs12, String.Empty);
                }
                else
                {
                    data = certificate.RawData;
                }

                // build key pair and store in NV storage on TPM.
                // TODO
            }

            return Task.CompletedTask;
        }

        public Task<bool> Delete(string thumbprint)
        {
            lock (m_lock)
            {
                bool found = false;
                X509Certificate2 entry = Find(thumbprint);
                if (entry != null)
                {
                    //TODO: Generate keypair and delete from NV storage
                    found = true;
                }

                return Task.FromResult(found);
            }
        }

        public Task<X509Certificate2Collection> FindByThumbprint(string thumbprint)
        {
            X509Certificate2Collection certificates = new X509Certificate2Collection();

            lock (m_lock)
            {
                X509Certificate2 entry = Find(thumbprint);
                if (entry != null)
                {
                    certificates.Add(entry);
                }

                return Task.FromResult(certificates);
            }
        }
        
        public bool SupportsPrivateKeys
        {
            get
            {
                return true;
            }
        }

        public string GetPrivateKeyFilePath(string thumbprint)
        {
            X509Certificate2 entry = Find(thumbprint);

            if (entry == null)
            {
                return null;
            }

            if (!entry.HasPrivateKey)
            {
                return null;
            }

            return entry.Subject;
        }

        public string[] GetCrlFilePaths(string thumbprint)
        {
            List<string> filePaths = new List<string>();

            X509Certificate2 entry = Find(thumbprint);

            DirectoryInfo info = new DirectoryInfo(Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + "crl");

            foreach (FileInfo file in info.GetFiles("*.crl"))
            {
                X509CRL crl = null;

                try
                {
                    crl = new X509CRL(file.FullName);
                }
                catch (Exception e)
                {
                    Utils.Trace(e, "Could not parse CRL file.");
                    continue;
                }

                if (!Utils.CompareDistinguishedName(crl.Issuer, entry.Subject))
                {
                    continue;
                }

                filePaths.Add(file.FullName);
            }

            return filePaths.ToArray();
        }

        public X509Certificate2 LoadPrivateKey(string thumbprint, string subjectName, string password)
        {
            byte[] rawData = new byte[256];
            try
            {
                X509Certificate2 certificate = null;
                RSA rsa = null;
                try
                {
                    certificate = new X509Certificate2(
                        rawData,
                        (password == null) ? String.Empty : password,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                catch (Exception)
                {
                    certificate = new X509Certificate2(
                        rawData,
                        (password == null) ? String.Empty : password,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                if (rsa != null)
                {
                    int inputBlockSize = rsa.KeySize / 8 - 42;
                    byte[] bytes1 = rsa.Encrypt(new byte[inputBlockSize], RSAEncryptionPadding.OaepSHA1);
                    byte[] bytes2 = rsa.Decrypt(bytes1, RSAEncryptionPadding.OaepSHA1);
                    if (bytes2 != null)
                    {
                        return certificate;
                    }
                }
            }
            catch (Exception e)
            {
                Utils.Trace(e, "Could not load private key for certificate " + subjectName);
            }

            return null;
        }

        public bool SupportsCRLs { get { return true; } }

        public StatusCode IsRevoked(X509Certificate2 issuer, X509Certificate2 certificate)
        {
            if (issuer == null)
            {
                throw new ArgumentNullException("issuer");
            }

            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }

            // check for CRL.
            DirectoryInfo info = new DirectoryInfo(Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + "crl");

            if (info.Exists)
            {
                bool crlExpired = true;

                foreach (FileInfo file in info.GetFiles("*.crl"))
                {
                    X509CRL crl = null;

                    try
                    {
                        crl = new X509CRL(file.FullName);
                    }
                    catch (Exception e)
                    {
                        Utils.Trace(e, "Could not parse CRL file.");
                        continue;
                    }

                    if (!Utils.CompareDistinguishedName(crl.Issuer, issuer.Subject))
                    {
                        continue;
                    }

                    if (!crl.VerifySignature(issuer, false))
                    {
                        continue;
                    }

                    if (crl.IsRevoked(certificate))
                    {
                        return StatusCodes.BadCertificateRevoked;
                    }

                    if (crl.UpdateTime <= DateTime.UtcNow && (crl.NextUpdateTime == DateTime.MinValue || crl.NextUpdateTime >= DateTime.UtcNow))
                    {
                        crlExpired = false;
                    }
                }

                // certificate is fine.
                if (!crlExpired)
                {
                    return StatusCodes.Good;
                }
            }

            // can't find a valid CRL.
            return StatusCodes.BadCertificateRevocationUnknown;
        }

        /// <summary>
        /// Returns the CRLs in the store.
        /// </summary>
        public List<X509CRL> EnumerateCRLs()
        {
            List<X509CRL> crls = new List<X509CRL>();

            // check for CRL.
            DirectoryInfo info = new DirectoryInfo(Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + "crl");

            if (info.Exists)
            {
                foreach (FileInfo file in info.GetFiles("*.crl"))
                {
                    X509CRL crl = new X509CRL(file.FullName);
                    crls.Add(crl);
                }
            }

            return crls;
        }

        /// <summary>
        /// Returns the CRLs for the issuer.
        /// </summary>
        public List<X509CRL> EnumerateCRLs(X509Certificate2 issuer)
        {
            if (issuer == null)
            {
                throw new ArgumentNullException("issuer");
            }

            List<X509CRL> crls = new List<X509CRL>();

            // check for CRL.
            DirectoryInfo info = new DirectoryInfo(Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + "crl");

            if (info.Exists)
            {
                foreach (FileInfo file in info.GetFiles("*.crl"))
                {
                    X509CRL crl = new X509CRL(file.FullName);

                    if (!Utils.CompareDistinguishedName(crl.Issuer, issuer.Subject))
                    {
                        continue;
                    }

                    if (!crl.VerifySignature(issuer, false))
                    {
                        continue;
                    }

                    if (crl.UpdateTime <= DateTime.UtcNow && (crl.NextUpdateTime == DateTime.MinValue || crl.NextUpdateTime >= DateTime.UtcNow))
                    {
                        crls.Add(crl);
                    }
                }
            }

            return crls;
        }

        /// <summary>
        /// Adds a CRL to the store.
        /// </summary>
        public async void AddCRL(X509CRL crl)
        {
            if (crl == null)
            {
                throw new ArgumentNullException("crl");
            }

            X509Certificate2 issuer = null;
            X509Certificate2Collection certificates = await Enumerate();
            foreach (X509Certificate2 certificate in certificates)
            {
                if (Utils.CompareDistinguishedName(certificate.Subject, crl.Issuer))
                {
                    if (crl.VerifySignature(certificate, false))
                    {
                        issuer = certificate;
                        break;
                    }
                }
            }

            if (issuer == null)
            {
                throw new ServiceResultException(StatusCodes.BadCertificateInvalid, "Could not find issuer of the CRL.");
            }

            StringBuilder builder = new StringBuilder();
            builder.Append(Directory.GetCurrentDirectory());
            
            builder.Append(Path.DirectorySeparatorChar + "crl" + Path.DirectorySeparatorChar);
            builder.Append(GetFileName(issuer));
            builder.Append(".crl");

            FileInfo fileInfo = new FileInfo(builder.ToString());

            if (!fileInfo.Directory.Exists)
            {
                fileInfo.Directory.Create();
            }

            File.WriteAllBytes(fileInfo.FullName, crl.RawData);
        }

        /// <summary>
        /// Removes a CRL from the store.
        /// </summary>
        public bool DeleteCRL(X509CRL crl)
        {
            if (crl == null)
            {
                throw new ArgumentNullException("crl");
            }

            string filePath = Directory.GetCurrentDirectory();
            filePath += Path.DirectorySeparatorChar + "crl";

            DirectoryInfo dirInfo = new DirectoryInfo(filePath);

            if (dirInfo.Exists)
            {
                foreach (FileInfo fileInfo in dirInfo.GetFiles("*.crl"))
                {
                    if (fileInfo.Length == crl.RawData.Length)
                    {
                        byte[] bytes = File.ReadAllBytes(fileInfo.FullName);

                        if (Utils.IsEqual(bytes, crl.RawData))
                        {
                            fileInfo.Delete();
                            return true;
                        }
                    }
                }
            }

            return false;
        }

#region Private Methods
        /// <summary>
        /// Reads the current contents of the directory from disk.
        /// </summary>
        private IDictionary<string, X509Certificate2> Load(string thumbprint)
        {
            lock (m_lock)
            {
                m_certificates.Clear();
                
                //TODO: Load certs from TPM
                
                return m_certificates;
            }
        }

        private X509Certificate2 Find(string thumbprint)
        {
            IDictionary<string, X509Certificate2> certificates = Load(thumbprint);

            X509Certificate2 entry = null;

            if (!String.IsNullOrEmpty(thumbprint))
            {
                if (!certificates.TryGetValue(thumbprint, out entry))
                {
                    return null;
                }
            }

            return entry;
        }

        private string GetFileName(X509Certificate2 certificate)
        {
            // build file name.
            string commonName = certificate.FriendlyName;

            List<string> names = Utils.ParseDistinguishedName(certificate.Subject);

            for (int ii = 0; ii < names.Count; ii++)
            {
                if (names[ii].StartsWith("CN="))
                {
                    commonName = names[ii].Substring(3).Trim();
                    break;
                }
            }

            StringBuilder fileName = new StringBuilder();

            // remove any special characters.
            for (int ii = 0; ii < commonName.Length; ii++)
            {
                char ch = commonName[ii];

                if ("<>:\"/\\|?*".IndexOf(ch) != -1)
                {
                    ch = '+';
                }

                fileName.Append(ch);
            }

            fileName.Append(" [");
            fileName.Append(certificate.Thumbprint);
            fileName.Append("]");

            return fileName.ToString();
        }
#endregion

#region Private Fields
        private object m_lock = new object();
        private Tpm2Device m_tpmDevice = new TbsDevice();
        private Tpm2 m_tpm;
        private Dictionary<string, X509Certificate2> m_certificates;
#endregion
    }
}
