using System;
using System.Management.Automation;

namespace IISResetMe.PshUtils
{
    [Cmdlet(VerbsCommon.New,"RSAKeyPair")]
    public class NewRSAKeyPair : Cmdlet
    {
        [Parameter(Mandatory = true, Position = 0)]
        public int KeySize = 2048;

        protected override void BeginProcessing()
        {
            CryptoKnife.RSAKeyPair keyPair = CryptoKnife.NewRSAKey(KeySize);

            PSObject KeyPair = new PSObject();
            KeyPair.Members.Add(new PSNoteProperty("PrivateKey", keyPair.PrivateKey));
            KeyPair.Members.Add(new PSNoteProperty("PublicKey", keyPair.PublicKey));
            this.WriteObject(KeyPair);
        }
    }
}
