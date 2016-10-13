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
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Opc.Ua
{
    /// <summary>
    /// The identifier for an X509 certificate.
    /// </summary>
    public partial class CertificateIdentifier : IFormattable
    {
        #region IFormattable Members
        /// <summary>
        /// Formats the value of the current instance using the specified format.
        /// </summary>
        /// <param name="format">The <see cref="T:System.String"/> specifying the format to use.
        /// -or-
        /// null to use the default format defined for the type of the <see cref="T:System.IFormattable"/> implementation.</param>
        /// <param name="formatProvider">The <see cref="T:System.IFormatProvider"/> to use to format the value.
        /// -or-
        /// null to obtain the numeric format information from the current locale setting of the operating system.</param>
        /// <returns>
        /// A <see cref="T:System.String"/> containing the value of the current instance in the specified format.
        /// </returns>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            if (!String.IsNullOrEmpty(format))
            {
                throw new FormatException();
            }

            return ToString();
        }
        #endregion

        #region Overridden Methods
        /// <summary>
        /// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </returns>
        public override string ToString()
        {
            if (m_certificate != null)
            {
                return GetDisplayName(m_certificate);
            }

            if (m_subjectName != null)
            {
                return m_subjectName;
            }

            return m_thumbprint;
        }

        /// <summary>
        /// Returns true if the objects are equal.
        /// </summary>
        public override bool Equals(object obj)
        {
            if (Object.ReferenceEquals(this, obj))
            {
                return true;
            }

            CertificateIdentifier id = obj as CertificateIdentifier;

            if (id == null)
            {
                return false;
            }

            if (m_certificate != null && id.m_certificate != null)
            {
                return m_certificate.Thumbprint == id.m_certificate.Thumbprint;
            }

            if (Thumbprint == id.Thumbprint)
            {
                return true;
            }

            if (m_storeLocation != id.m_storeLocation)
            {
                return false;
            }

            if (m_storeName != id.m_storeName)
            {
                return false;
            }

            if (SubjectName != id.SubjectName)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Returns a suitable hash code.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Gets or sets the validation options.
        /// </summary>
        /// <value>
        /// The validation options that can be used to suppress certificate validation errors.
        /// </value>
        public CertificateValidationOptions ValidationOptions
        {
            get { return m_validationOptions; }
            set { m_validationOptions = value; }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Gets or sets the actual certificate.
        /// </summary>
        /// <value>The X509 certificate used by this instance.</value>
        public X509Certificate2 Certificate
        {
            get { return m_certificate; }
            set { m_certificate = value; }
        }

        /// <summary>
        /// Finds a certificate in a store.
        /// </summary>
        public async Task<X509Certificate2> Find()
        {
            return await Find(false);
        }

        /// <summary>
        /// Loads the application certificate with an optional password.
        /// </summary>
        public async Task<X509Certificate2> LoadApplicationCertificate(string applicationURI, string password)
        {
            if (this.StoreType == CertificateStoreType.Directory)
            {
                DirectoryCertificateStore.Instance.Open(this.StorePath);
                m_certificate = DirectoryCertificateStore.Instance.LoadApplicationCertificate(this.Thumbprint, this.SubjectName, applicationURI, password);
                return m_certificate;
            }
            else if (this.StoreType == CertificateStoreType.TPM)
            {

                TPMCertificateStore.Instance.Open(this.StorePath);
                m_certificate = TPMCertificateStore.Instance.LoadApplicationCertificate(this.Thumbprint, this.SubjectName, applicationURI, password);
                return m_certificate;
            }
            else
            {
                return await Find(true);
            }
        }

        /// <summary>
        /// Finds a certificate in a store.
        /// </summary>
        /// <param name="needPrivateKey">if set to <c>true</c> the returned certificate must contain the private key.</param>
        /// <returns>An instance of the <see cref="X509Certificate2"/> that is emebeded by this instance or find it in 
        /// the selected strore pointed out by the <see cref="StorePath"/> using selected <see cref="SubjectName"/>.</returns>
        public async Task<X509Certificate2> Find(bool needPrivateKey)
        {
            X509Certificate2 certificate = null;

            // check if the entire certificate has been specified.
            if (m_certificate != null)
            {
                certificate = m_certificate;
            }
            else
            {
                // open store.
                ICertificateStore store = CertificateStoreIdentifier.PickStore(StoreType);
                
                store.Open(StorePath);

                X509Certificate2Collection collection = await store.Enumerate();

                certificate = Find(collection, m_thumbprint, m_subjectName, needPrivateKey);

                if (certificate != null)
                {
                    m_certificate = certificate;
                }
                
            }

            return certificate;
        }

        /// <summary>
        /// Returns a display name for a certificate.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <returns>
        /// A string containg FriendlyName of the <see cref="X509Certificate2"/> or created using Subject of 
        /// the <see cref="X509Certificate2"/>.
        /// </returns>
        private static string GetDisplayName(X509Certificate2 certificate)
        {
            if (!String.IsNullOrEmpty(certificate.FriendlyName))
            {
                return certificate.FriendlyName;
            }

            string name = certificate.Subject;

            // find the common name delimiter.
            int index = name.IndexOf("CN", StringComparison.Ordinal);

            if (index == -1)
            {
                return name;
            }

            StringBuilder buffer = new StringBuilder(name.Length);

            // skip characters until finding the '=' character
            for (int ii = index + 2; ii < name.Length; ii++)
            {
                if (name[ii] == '=')
                {
                    index = ii + 1;
                    break;
                }
            }

            // skip whitespace.
            for (int ii = index; ii < name.Length; ii++)
            {
                if (!Char.IsWhiteSpace(name[ii]))
                {
                    index = ii;
                    break;
                }
            }

            // read the common until finding a ','.
            for (int ii = index; ii < name.Length; ii++)
            {
                if (name[ii] == ',')
                {
                    break;
                }

                buffer.Append(name[ii]);
            }

            return buffer.ToString();
        }

        /// <summary>
        /// Finds a certificate in the specified collection.
        /// </summary>
        /// <param name="collection">The collection.</param>
        /// <param name="thumbprint">The thumbprint of the certificate.</param>
        /// <param name="subjectName">Subject name of the certificate.</param>
        /// <param name="needPrivateKey">if set to <c>true</c> [need private key].</param>
        /// <returns></returns>
        public static X509Certificate2 Find(X509Certificate2Collection collection, string thumbprint, string subjectName, bool needPrivateKey)
        {
            // find by thumbprint.
            if (!String.IsNullOrEmpty(thumbprint))
            {
                collection = collection.Find(X509FindType.FindByThumbprint, thumbprint, false);

                foreach (X509Certificate2 certificate in collection)
                {
                    if (String.IsNullOrEmpty(subjectName))
                    {
                        // return the first one
                        return certificate;
                    }

                    List<string> subjectName2 = Utils.ParseDistinguishedName(subjectName);

                    if (Utils.CompareDistinguishedName(certificate, subjectName2))
                    {
                        return certificate;
                    }
                }

                return null;
            }
            // find by subject name.
            if (!String.IsNullOrEmpty(subjectName))
            {
                List<string> subjectName2 = Utils.ParseDistinguishedName(subjectName);

                foreach (X509Certificate2 certificate in collection)
                {
                    if (Utils.CompareDistinguishedName(certificate, subjectName2))
                    {
                        return certificate;
                    }
                }

                collection = collection.Find(X509FindType.FindBySubjectName, subjectName, false);

                foreach (X509Certificate2 certificate in collection)
                {
                    return certificate;
                }
            }

            // certificate not found.
            return null;
        }
        #endregion
    }

    #region CertificateIdentifierCollection Class
    /// <summary>
    /// A collection of CertificateIdentifier objects.
    /// </summary>
    public partial class CertificateIdentifierCollection
    {
        /// <summary>
        /// Creates a new object that is a copy of the current instance.
        /// </summary>
        /// <returns>
        /// A new object that is a copy of this instance.
        /// </returns>
        public new object MemberwiseClone()
        {
            CertificateIdentifierCollection collection = new CertificateIdentifierCollection();

            for (int ii = 0; ii < this.Count; ii++)
            {
                collection.Add((CertificateIdentifier)Utils.Clone(this[ii]));
            }

            return collection;
        }
        
        #region IDisposable Members
        /// <summary>
        /// Frees any unmanaged resources.
        /// </summary>
        public void Dispose()
        {   
            Dispose(true);
        }

        /// <summary>
        /// An overrideable version of the Dispose.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // nothing to do.
            }
        }
        #endregion

        #region ICertificateStore Members
        /// <summary>
        /// Opens the store at the specified location.
        /// </summary>
        /// <param name="location">The location.</param>
        /// <remarks>
        /// The syntax depends on the store implementation.
        /// </remarks>
        public void Open(string location)
        {
            // nothing to do.
        }

        /// <summary>
        /// Closes the store.
        /// </summary>
        public void Close()
        {
            // nothing to do.
        }

        /// <summary>
        /// Enumerates the certificates in the store.
        /// </summary>
        /// <remarks>
        /// Identifiers which do not refer to valid certificates are ignored.
        /// </remarks>
        /// <returns>The list of valid certificates in the store.</returns>
        public async Task<X509Certificate2Collection> Enumerate()
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();

            for (int ii = 0; ii < this.Count; ii++)
            {
                X509Certificate2 certificate = await this[ii].Find(false);

                if (certificate != null)
                {
                    collection.Add(certificate);
                }
            }

            return collection;
        }

        /// <summary>
        /// Adds a certificate to the store.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        public async Task Add(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException("certificate");

            for (int ii = 0; ii < this.Count; ii++)
            {
                X509Certificate2 current = await this[ii].Find(false);

                if (current != null && current.Thumbprint == certificate.Thumbprint)
                {
                    throw ServiceResultException.Create(
                        StatusCodes.BadEntryExists,
                        "A certificate with the specified thumbprint already exists. Subject={0}, Thumbprint={1}",
                        certificate.SubjectName,
                        certificate.Thumbprint);
                }
            }

            this.Add(new CertificateIdentifier(certificate));
        }

        /// <summary>
        /// Deletes a certificate from the store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint.</param>
        /// <returns>True if the certificate exists.</returns>
        public async Task<bool> Delete(string thumbprint)
        {
            if (String.IsNullOrEmpty(thumbprint))
            {
                return false;
            }

            for (int ii = 0; ii < this.Count; ii++)
            {
                X509Certificate2 certificate = await this[ii].Find(false);

                if (certificate != null && certificate.Thumbprint == thumbprint)
                {
                    this.RemoveAt(ii);
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Finds the certificate with the specified thumprint.
        /// </summary>
        /// <param name="thumbprint">The thumbprint.</param>
        /// <returns>The matching certificate</returns>
        public async Task<X509Certificate2> FindByThumbprint(string thumbprint)
        {
            if (String.IsNullOrEmpty(thumbprint))
            {
                return null;
            }

            for (int ii = 0; ii < this.Count; ii++)
            {
                X509Certificate2 certificate = await this[ii].Find(false);

                if (certificate != null && certificate.Thumbprint == thumbprint)
                {
                    return certificate;
                }
            }

            return null;
        }

        /// <summary>
        /// Whether the store support CRLs.
        /// </summary>
        public bool SupportsCRLs { get { return false; } }

        /// <summary>
        /// Checks if issuer has revoked the certificate.
        /// </summary>
        public StatusCode IsRevoked(X509Certificate2 issuer, X509Certificate2 certificate)
        {
            return StatusCodes.BadNotSupported;
        }

        /// <summary>
        /// Returns the CRLs in the store.
        /// </summary>
        public List<X509CRL> EnumerateCRLs()
        {
            return new List<X509CRL>();
        }

        /// <summary>
        /// Returns the CRLs for the issuer.
        /// </summary>
        public List<X509CRL> EnumerateCRLs(X509Certificate2 issuer)
        {
            return new List<X509CRL>();
        }        
        
        /// <summary>
        /// Adds a CRL to the store.
        /// </summary>
        public void AddCRL(X509CRL crl)
        {
            throw new ServiceResultException(StatusCodes.BadNotSupported);
        }

        /// <summary>
        /// Removes a CRL from the store.
        /// </summary>
        public bool DeleteCRL(X509CRL crl)
        {
            throw new ServiceResultException(StatusCodes.BadNotSupported);
        }
        #endregion
    }
    #endregion

    #region CertificateValidationOptions Class
    /// <summary>
    /// Options that can be used to suppress certificate validation errors.
    /// </summary>
    [Flags]
    public enum CertificateValidationOptions
    {
        /// <summary>
        /// Use the default options.
        /// </summary>
        Default = 0x0,

        /// <summary>
        /// Ignore expired certificates.
        /// </summary>
        SuppressCertificateExpired = 0x1,

        /// <summary>
        /// Ignore mismatches between the URL and the DNS names in the certificate.
        /// </summary>
        SuppressHostNameInvalid = 0x2,

        /// <summary>
        /// Ignore errors when it is not possible to check the revocation status for a certificate.
        /// </summary>
        SuppressRevocationStatusUnknown = 0x8,

        /// <summary>
        /// Attempt to check the revocation status online.
        /// </summary>
        CheckRevocationStatusOnline = 0x10,

        /// <summary>
        /// Attempt to check the revocation status offline.
        /// </summary>
        CheckRevocationStatusOffine = 0x20,

        /// <summary>
        /// Never trust the certificate.
        /// </summary>
        TreatAsInvalid = 0x40
    }
    #endregion
}
