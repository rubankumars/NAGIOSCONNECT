package com.plugins.nagios;
import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.AbstractProject;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import java.net.MalformedURLException;
import java.io.IOException;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.ParseException;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.util.Date;
import java.util.Calendar;
import java.text.SimpleDateFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Rubankumar
 * @email ruban.yuvaraj@gmail.com
 *
 */

public class NagiosConnect extends Builder {

    private final String servername;
    private final String jobname;
    int minutes = 0;
    private final String nagiosStatus;
    static HttpURLConnection connection = null; 

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public NagiosConnect(String servername, String jobname, int minutes, String nagiosStatus) {
        this.servername = servername;
	this.jobname = jobname;
	this.minutes = minutes;
	this.nagiosStatus = nagiosStatus;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     */
    public String getServername() {
        return servername;
    }
    public String getJobname() {
        return jobname;
    }
    public int getMinutes() {
        return minutes;
    }
    public String getNagiosStatus(){
	return nagiosStatus;
    }

	
	static TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
       		 public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            		return null;
       		 }	
        	 public void checkClientTrusted(X509Certificate[] certs, String authType) {
        	 }
        	 public void checkServerTrusted(X509Certificate[] certs, String authType) {
        	 }
    	 }
	};
	
	public static HttpURLConnection nagiosAuth(String NAGIOSURL,String user, String password) throws MalformedURLException, IOException{
                        final String username = user;
                        final String pass = password;
		
                        URL url = new URL(NAGIOSURL);
                        Authenticator.setDefault (new Authenticator() {
                                protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication (username, pass.toCharArray());
                                }
                        });

                        connection = (HttpURLConnection)url.openConnection();
			return connection;
		/*catch (Exception e) {
                                StringWriter errors =  new StringWriter();
                                e.printStackTrace(new PrintWriter(errors));
                                return errors.toString();
                 } */

	}

	public static String excutePost(String NAGIOSURL, String URLPARAMETER, String user, String password, boolean sslCheck) {
//		  HttpURLConnection connection = null; 
			final String username = user;
			final String pass = password;
			final boolean ssl = sslCheck;
		  try {
			if (ssl){
		                // Install the all-trusting trust manager
			        SSLContext sc = SSLContext.getInstance("SSL");
		       		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		        	HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory()); 
		        
			        // Create all-trusting host name verifier
			        HostnameVerifier allHostsValid = new HostnameVerifier() {
			            public boolean verify(String hostname, SSLSession session) {
			                return true;
			            }
			        };
		        
			        // Install the all-trusting host verifier
			        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
			}

		    	//Create connection
/*		    	URL url = new URL(NAGIOSURL);
		    	Authenticator.setDefault (new Authenticator() {
		        	protected PasswordAuthentication getPasswordAuthentication() {
		            	return new PasswordAuthentication (username, pass.toCharArray());
		        	}
		   	});
		    
		    	connection = (HttpURLConnection)url.openConnection();*/
			connection = nagiosAuth(NAGIOSURL,username,pass);
		    	connection.setRequestMethod("POST");
		    	connection.setRequestProperty("Content-Type", 
		        "application/x-www-form-urlencoded");
		    	connection.setRequestProperty("Content-Length",Integer.toString(URLPARAMETER.getBytes().length));
		    	connection.setRequestProperty("Content-Language", "en-US");  
		    	connection.setUseCaches(false);
		    	connection.setDoOutput(true);

		    	//Send request
		    	DataOutputStream wr = new DataOutputStream (
		        connection.getOutputStream());
		    	wr.writeBytes(URLPARAMETER);
		    	wr.close();

		    	//Get Response  
		    	InputStream is = connection.getInputStream();
		    	BufferedReader rd = new BufferedReader(new InputStreamReader(is));
		  	StringBuffer response = new StringBuffer();
		    	String line;
		    	while((line = rd.readLine()) != null) {
		      		response.append(line);
		      		response.append('\r');
		      	}
		    	rd.close();
		    	return response.toString();
		  	} catch (Exception e) {
				StringWriter errors =  new StringWriter();
				e.printStackTrace(new PrintWriter(errors));
				return errors.toString();
		  	} finally {
		    		if(connection != null) {
		      		connection.disconnect(); 
		    	}
		  	}
		}

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) {
        
	    listener.getLogger().println("ServerName you have entered is " + servername);
            listener.getLogger().println("JobName you have entered is " + jobname);
            listener.getLogger().println("Minutes you have entered is " + minutes);
            listener.getLogger().println("Service entered is " + nagiosStatus);

            final String url = getDescriptor().getNagiosUrl();
            final String user = getDescriptor().getNagiosUser();
            final String password = getDescriptor().getNagiosPassword();
	    final String NAGIOSURL = url + "/cgi-bin/cmd.cgi";
	    final boolean sslCheck = getDescriptor().getSslCheck();

	    String pattern =  "MM-dd-yyy HH:mm:ss";
	    SimpleDateFormat format = new SimpleDateFormat(pattern);
	    Date now = new Date();
	    String startDate = format.format(now);
		Date advanceTime = null;
		try{
			advanceTime = format.parse(startDate);
		}catch (ParseException e) {
                        StringWriter errors =  new StringWriter();
                        e.printStackTrace(new PrintWriter(errors));
			listener.getLogger().println(errors.toString());
		} 
	    Calendar cal = Calendar.getInstance();
	    cal.setTime(advanceTime);
	    cal.add(Calendar.MINUTE, minutes);
	    String endDate =  format.format(cal.getTime());

            listener.getLogger().println("StartDate " + startDate);
            listener.getLogger().println("EndDate " + endDate);

		if(nagiosStatus.equals("nagiosPause")){
                	String URLPARAMETER = "cmd_typ=56&cmd_mod=2&host="+servername+"&service="+jobname+"&com_data=Build and Deploy is in progress&trigger=0&start_time="+startDate+"&end_time="+endDate+"&fixed=1&hours=2&minutes=0&btnSubmit=Commit";
                	String data = excutePost(NAGIOSURL,URLPARAMETER,user,password,sslCheck);
		 		
				if (data.contains("Your command request was successfully submitted to Nagios for processing")){
        	 			listener.getLogger().println(minutes+" min(s) downtime has been scheduled for the service '"+jobname+"' on server '"+servername+"'");
         			}else if (data.contains("errorMessage")){
        	 			for(int index = data.indexOf("errorMessage");index>=0; index = data.indexOf("errorMessage", index+1))
             				{
        		 	 		listener.getLogger().println("We got the below error message from NAGIOS, please check your configuration...\n");
                     				String error = data.substring(index+14, index+80);
                     				listener.getLogger().println(error);
             				}

				}else{
					listener.getLogger().println(data);
				}
		}
		else if (nagiosStatus.equals("nagiosStart")){
			final String NAGIOSURL_DOWNID = url + "/cgi-bin/extinfo.cgi";
			String URLPARAMETER = "type=6";
			String output=excutePost(NAGIOSURL_DOWNID,URLPARAMETER,user,password,sslCheck);
			for(int index = output.indexOf("down_id");index>=0; index = output.indexOf("down_id", index+1))
			{
				String a = output.substring(index-500, index+15);
				if ( (a.indexOf(servername)>-1) && (a.indexOf(jobname)>-1) ){
				String b = output.substring(index, index+20);
				String downtime_ID =  (b.substring(8, b.indexOf("'><"))).trim();
				String URLPARAMETER_DEL = "cmd_mod=2&cmd_typ=79&down_id="+downtime_ID+"btnSubmit=Commit";
				String data = excutePost(NAGIOSURL,URLPARAMETER_DEL,user,password,sslCheck);		
			
                                if (data.contains("Your command request was successfully submitted to Nagios for processing")){
                                        listener.getLogger().println("Downtime ID - " + downtime_ID+ " with reference to the service '"+jobname+"' and the server '"+servername+"' is enabled for notification");
                                }else if (data.contains("errorMessage")){
                                        for(int erridx = data.indexOf("errorMessage");erridx>=0; index = data.indexOf("errorMessage", erridx+1))
                                        {
                                                listener.getLogger().println("We got the below error message from NAGIOS, please check your configuration...\n");
                                                String error = data.substring(erridx+14, erridx+80);
                                                listener.getLogger().println(error);
                                        }

                                }else{
                                        listener.getLogger().println(data);
                                }

				}
			}
	       }
	return true;
    }

	private static boolean IsMatch(String s, String pattern) {
        	try {
            		Pattern patt = Pattern.compile(pattern);
            		Matcher matcher = patt.matcher(s);
	                return matcher.matches();
	        } catch (RuntimeException e) {
		        return false;
	    	}       
	}
	
    // Overridden for better type safety.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link NagiosConnect}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */
        private String nagiosUrl;
        private String nagiosUser;
        private String nagiosPassword;
	private boolean sslCheck;

        /**
         * Performs on-the-fly validation of the form field 'name'.
         *
         * @param value
         *      This parameter receives the value that the user has typed.
         * @return
         *      Indicates the outcome of the validation. This is sent to the browser.
         */
        public FormValidation doCheckName(@QueryParameter String nagiosUrl, @QueryParameter String nagiosUser, @QueryParameter String nagiosPassword) throws IOException, ServletException {
	
	String URL_PATTERN = "^(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";

	            if (nagiosUrl.length() > 0)
			 connection = nagiosAuth(nagiosUrl,nagiosUser,nagiosPassword);
				 if((connection.getResponseMessage().equals("OK")) && (IsMatch(nagiosUrl,URL_PATTERN)))
					return FormValidation.ok();				
				 
				else 
					return FormValidation.error(connection.getResponseMessage());
	    	     
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types 
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Nagios Configuration";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            // To persist global configuration information,
            // set that to properties and call save().
            nagiosUrl = formData.getString("nagiosUrl");
	    nagiosUser = formData.getString("nagiosUser");
	    nagiosPassword = formData.getString("nagiosPassword");
	    sslCheck =  formData.getBoolean("sslCheck");
            // Can also use req.bindJSON(this, formData);
            // (easier when there are many fields; need set* methods for this)
            save();
            return super.configure(req,formData);
        }

        /**
         * This method returns the global configuration values set for NAGIOS configuration
         */
       public String getNagiosUrl() {
         return nagiosUrl;
       }

       public String getNagiosUser() {
         return nagiosUser;
       }

       public String getNagiosPassword() {
         return nagiosPassword;
       }

       public boolean getSslCheck() {
         return sslCheck;
       }

    }
}

