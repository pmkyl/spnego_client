package codes.rb;

import org.ietf.jgss.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Base64;
//import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try {
            System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
            Oid krb5MechOid = new Oid("1.2.840.113554.1.2.2");
            Oid spnegoMechOid = new Oid("1.3.6.1.5.5.2");

            GSSManager manager = GSSManager.getInstance();
            GSSName gssUserName = manager.createName("jirky@EXAMPLE.COM", GSSName.NT_USER_NAME, krb5MechOid);
            org.ietf.jgss.GSSCredential clientGssCreds = manager.createCredential(gssUserName.canonicalize(krb5MechOid),
                    GSSCredential.INDEFINITE_LIFETIME,
                    krb5MechOid,
                    GSSCredential.INITIATE_ONLY);
            clientGssCreds.add(gssUserName,
                    GSSCredential.INDEFINITE_LIFETIME,
                    GSSCredential.INDEFINITE_LIFETIME,
                    spnegoMechOid,
                    GSSCredential.INITIATE_ONLY);
            System.out.println(clientGssCreds.toString());


            GSSName gssServerName = manager.createName("http/monarch.example.com@EXAMPLE.COM", GSSName.NT_USER_NAME);
            GSSContext clientContext = manager.createContext(gssServerName.canonicalize(spnegoMechOid),
                    spnegoMechOid,
                    clientGssCreds,
                    GSSContext.DEFAULT_LIFETIME);
            // optional enable GSS credential delegation
            clientContext.requestCredDeleg(true);
            byte[] spnegoToken = new byte[0];
            // create a SPNEGO token for the target server
            spnegoToken = clientContext.initSecContext(spnegoToken, 0, spnegoToken.length);
            URL url = new URL("http://localhost:8080/");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            try {
                // insert SPNEGO token in the HTTP header
                byte[] tkn = Base64.getEncoder().encode(spnegoToken);
                System.out.printf(new String(tkn));
                con.setRequestProperty("Authorization", "Negotiate " + new String(tkn));
                con.getResponseCode();
            } catch (IOException e) {
                System.out.printf(e.getMessage());
            } catch (Exception ex) {
                System.out.printf(ex.getMessage());
            }

        } catch (Exception e) {
            System.out.printf(e.getMessage());
        }
    }
}
