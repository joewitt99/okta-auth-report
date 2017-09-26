package oktareport;

import com.opencsv.CSVWriter;

import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represents unique login users.  This class can probably be simplified and rely on the csv output to
 * group logins by source.  LoginsByIdpSource hashmap is useless at this point, since it was only used for
 * reporting in the console reporting.  Revisit based on feedback.
 */
public class UniqueUsers {

    private HashMap<String, BCBSALoginUser> loginUsers = new HashMap<String, BCBSALoginUser>();
    private HashMap<String, HashMap<String, Integer>> loginsByIdpSource = new HashMap<String, HashMap<String, Integer>>();

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
            BCBSALoginUser user = new BCBSALoginUser(userId, requestId, "");
            loginUsers.put(userId, user);
        }
    }

    private void addSource(String userId, String requestId, String idpSource) {
        loginUsers.get(userId).addIdpSource(requestId, idpSource); //must exist
        if(loginsByIdpSource.containsKey(idpSource)) {
            if (loginsByIdpSource.get(idpSource).containsKey(userId)) {
                int value = loginsByIdpSource.get(idpSource).get(userId).intValue();
                loginsByIdpSource.get(idpSource).put(userId, value++);
            } else {
                loginsByIdpSource.get(idpSource).put(userId, 1);
            }
        } else {
            HashMap<String, Integer> userMap = new HashMap<String, Integer>();
            userMap.put(userId, 1);
            loginsByIdpSource.put(idpSource, userMap);
        }
    }

    public static int getUniqueAuthCount() {
        return uniqueUsers.loginUsers.size();
    }

    public static HashMap<String, Integer> getUniqueByIdpSources() {
        HashMap<String, Integer> counts = new HashMap<String, Integer>();
        uniqueUsers.loginsByIdpSource.forEach((source, userMap) -> {
            counts.put(source, userMap.size());
        });
        return counts;
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

    private class BCBSALoginUser {
        private String userId;
        private int authCount;
        private String idpSource = "local";
        private HashMap<String, String> requestIDPMap = new HashMap<String, String>(); //Look at memory consumption on large dataloads this could be removed.

        public BCBSALoginUser(String userId, String requestId, String idpSource) {
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
            return this.userId.equals(((BCBSALoginUser)user).userId)?true:false;
        }

        @Override
        public int hashCode() {
            int result = 17;
            return 31 * result + this.userId.hashCode();
        }
    }
}
