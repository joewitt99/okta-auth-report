package oktareport;

import com.opencsv.CSVWriter;

import java.io.FileWriter;
import java.net.URL;
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
    private static final SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    private static UniqueUsers uniqueUsers = null;

    private UniqueUsers() {

    }

    public static void addUser(String userId, Date published, String requestId) {
        if(uniqueUsers == null) {
            uniqueUsers = new UniqueUsers();
        }
        uniqueUsers.add(userId, published, requestId);
    }

    public static void addIdpSource(String userId, String requestId, String idpSource) {
        if(uniqueUsers == null) {
            uniqueUsers = new UniqueUsers();
        }
        uniqueUsers.addSource(userId, requestId, idpSource);
    }

    private void add(String userId, Date published, String requestId) {
        if(loginUsers.containsKey(userId)) {
            loginUsers.get(userId).addAuth(requestId, published);
        } else {
            LoginUser user = new LoginUser(userId, requestId, "", published);
            loginUsers.put(userId, user);
        }
    }

    private void addSource(String userId, String requestId, String idpSource) {
        if(loginUsers.containsKey(userId)) {
            loginUsers.get(userId).addIdpSource(requestId, idpSource);
        } else {
            LoginUser user = new LoginUser(userId, requestId, idpSource);
            loginUsers.put(userId, user);
        }
    }

    public static int getUniqueAuthCount() {
        return uniqueUsers.loginUsers.size();
    }


    public static void getCSV(String oktaOrg) {
        try {
            logger.info("Starting generation of CSV file...");
            URL netUrl = new URL(oktaOrg);
            String host = netUrl.getHost();
            String fileName = new SimpleDateFormat("'"+host+"-'yyyyMMddHHmm'.csv'").format(new Date());
            CSVWriter writer = new CSVWriter(new FileWriter(fileName));
            writer.writeNext(new String[] {"Login", "# Unique Auths", "# of Authentications", "Source"});
            uniqueUsers.loginUsers.forEach((userId, user) -> {
                String[] tokens = {userId, ""+user.uniqueAuthCount, ""+user.getAuthCount(), user.getIdpSource()};
                writer.writeNext(tokens);
            });
            writer.close();
        } catch(Exception e) {
            logger.error("Error writing CSV file...", e);
        } finally {
            logger.info("Finish generation of CSV file...");
        }
    }

    public static void getRawCSV(String oktaOrg) {
        try {
            logger.info("Starting generation of Raw CSV file...");
            URL netUrl = new URL(oktaOrg);
            String host = netUrl.getHost();
            String fileName = new SimpleDateFormat("'"+host+"-all-'yyyyMMddHHmm'.csv'").format(new Date());
            CSVWriter writer = new CSVWriter(new FileWriter(fileName));
            writer.writeNext(new String[] {"Login", "Date", "Source"});
            uniqueUsers.loginUsers.forEach((userId, user) -> {
                user.getAllRequests().forEach((requestId, login) -> {
                    String[] tokens = {userId, formatter.format(login), user.getIdpSource()};
                    writer.writeNext(tokens);
                });
            });
            writer.close();
        } catch(Exception e) {
            logger.error("Error writing CSV file...", e);
        } finally {
            logger.info("Finish generation of CSV file...");
        }
    }

    private static long HOURS24 = 86400000L;

    private class LoginUser {
        private String userId;
        private int authCount;
        private int uniqueAuthCount;
        private String idpSource = "local";
        private Date uniqueLoginDate; //This date represents the start of a 24 hour unique login calculation
        private Date loginDate;
        private HashMap<String, Date> requestIDPMap = new HashMap<String, Date>(); //Look at memory consumption on large dataloads this could be removed.

        public LoginUser(String userId, Date published) {
            this.userId = userId;
            this.loginDate = published;
            this.uniqueLoginDate = published;
        }

        public LoginUser(String userId, String requestId, String idpSource) {
            this.userId = userId;
            this.requestIDPMap.put(requestId, null);
            this.idpSource = idpSource;
        }

        public LoginUser(String userId, String requestId, String idpSource, Date published) {
            this.userId = userId;
            this.requestIDPMap.put(requestId, published);
            this.authCount = 1;
            this.uniqueAuthCount = 1;
            this.loginDate = published;
            this.uniqueLoginDate = published;
        }

        public void addAuth(String requestId, Date published) {
            //Check if this auth is 24 hours past the uniqueLoginDate.  If it is then this is a unique login count for this user.
            if(this.uniqueLoginDate == null) {
                this.uniqueLoginDate = published;
                this.uniqueAuthCount++;
            } else {
                long initial = this.uniqueLoginDate.getTime();
                long loginTime = published.getTime();
                if ((loginTime - initial) > HOURS24) {
                    this.uniqueAuthCount++;
                    this.uniqueLoginDate = published;
                }
            }
            this.authCount++;
            this.requestIDPMap.put(requestId, published);
        }

        public void addIdpSource(String requestId, String idpSource) {
            this.idpSource = idpSource;
            //this.requestIDPMap.put(requestId, published); //Look at memory consumption on large dataloads this could be removed.
        }

        public void setUniqueLoginDate(Date date) {
            this.uniqueLoginDate = date;
        }

        public Date getUniqueLoginDate() {
            return this.uniqueLoginDate;
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

        public HashMap<String, Date> getAllRequests() {
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
