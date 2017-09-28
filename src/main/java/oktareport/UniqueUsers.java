package oktareport;

import com.opencsv.CSVWriter;

import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represents unique login users.
 */
public class UniqueUsers {

    private HashMap<String, LoginUser> loginUsers = new HashMap<String, LoginUser>();

    private static final Logger logger = LogManager.getLogger(UniqueUsers.class);

    private static UniqueUsers uniqueUsers = null;

    private UniqueUsers() {

    }

    public static void addUser(String userId, String requestId) {
        if(uniqueUsers == null) {
            uniqueUsers = new UniqueUsers();
        }
        uniqueUsers.add(userId, requestId);
    }

    public static void addIdpSource(String userId, String requestId, String idpSource) {
        uniqueUsers.addSource(userId, requestId, idpSource);
    }

    private void add(String userId, String requestId) {
        if(loginUsers.containsKey(userId)) {
            loginUsers.get(userId).addAuth(requestId);
        } else {
            LoginUser user = new LoginUser(userId, requestId, "");
            loginUsers.put(userId, user);
        }
    }

    private void addSource(String userId, String requestId, String idpSource) {
        loginUsers.get(userId).addIdpSource(requestId, idpSource); //must exist
    }

    public static int getUniqueAuthCount() {
        return uniqueUsers.loginUsers.size();
    }


    public static void getCSV() {
        try {
            logger.info("Starting generation of CSV file...");
            String fileName = new SimpleDateFormat("'login-'yyyyMMddHHmm'.txt'").format(new Date());
            CSVWriter writer = new CSVWriter(new FileWriter(fileName));
            writer.writeNext(new String[] {"Login", "#of Authentications", "IDP Source"});
            uniqueUsers.loginUsers.forEach((userId, user) -> {
                String[] tokens = {userId, ""+user.getAuthCount(), user.getIdpSource()};
                writer.writeNext(tokens);
            });
            writer.close();
        } catch(Exception e) {
            logger.error("Error writing CSV file...", e);
        } finally {
            logger.info("Finish generation of CSV file...");
        }
    }

    private class LoginUser {
        private String userId;
        private int authCount;
        private String idpSource = "local";
        private HashMap<String, String> requestIDPMap = new HashMap<String, String>(); //Look at memory consumption on large dataloads this could be removed.

        public LoginUser(String userId, String requestId, String idpSource) {
            this.userId = userId;
            this.requestIDPMap.put(requestId, "");
            this.authCount = 1;
        }

        public void addAuth(String requestId) {
            this.authCount++;
            this.requestIDPMap.put(requestId, "local");
        }

        public void addIdpSource(String requestId, String idpSource) {
            this.idpSource = idpSource;
            this.requestIDPMap.put(requestId, idpSource); //Look at memory consumption on large dataloads this could be removed.
        }

        public String getUserId() {
            return this.userId;
        }

        public String getIdpSource() {
            return this.idpSource;
        }

        public int getAuthCount() {
            return this.authCount;
        }

        public HashMap<String, String> getAllRequests() {
            return this.requestIDPMap;
        }

        @Override
        public boolean equals(Object user) {
            return this.userId.equals(((LoginUser)user).userId)?true:false;
        }

        @Override
        public int hashCode() {
            int result = 17;
            return 31 * result + this.userId.hashCode();
        }
    }
}
