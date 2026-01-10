package org.siros.interop;

import java.io.File;
import java.security.KeyStore;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.base.id.factory.GlobalIDFactory;
import com.helger.base.id.factory.MemoryIntIDFactory;
import com.helger.phase4.crypto.AS4CryptoFactoryInMemoryKeyStore;
import com.helger.phase4.crypto.ECryptoAlgorithmSign;
import com.helger.phase4.crypto.ECryptoAlgorithmSignDigest;
import com.helger.phase4.incoming.AS4IncomingHandler;
import com.helger.phase4.incoming.AS4IncomingReceiverConfiguration;
import com.helger.phase4.incoming.AS4ServerInitializer;
import com.helger.phase4.incoming.servlet.AS4Servlet;
import com.helger.phase4.model.pmode.PMode;
import com.helger.phase4.model.pmode.PModeManager;
import com.helger.phase4.model.pmode.leg.EPModeSendReceiptReplyPattern;
import com.helger.phase4.model.pmode.leg.PModeAddressList;
import com.helger.phase4.model.pmode.leg.PModeLeg;
import com.helger.phase4.model.pmode.leg.PModeLegBusinessInformation;
import com.helger.phase4.model.pmode.leg.PModeLegProtocol;
import com.helger.phase4.model.pmode.leg.PModeLegSecurity;
import com.helger.phase4.model.pmode.leg.PModePayloadProfile;
import com.helger.phase4.util.AS4ResourceHelper;
import com.helger.photon.io.WebFileIO;
import com.helger.security.keystore.EKeyStoreType;
import com.helger.security.keystore.IKeyStoreAndKeyDescriptor;
import com.helger.security.keystore.KeyStoreAndKeyDescriptor;
import com.helger.servlet.mock.MockServletContext;
import com.helger.web.scope.mgr.WebScopeManager;

/**
 * Standalone phase4 test server for interoperability testing with go-as4.
 * 
 * This server:
 * - Accepts AS4 UserMessages from any sender
 * - Verifies RSA-SHA-256 signatures
 * - Returns signed Receipts
 * - Logs all received messages for verification
 */
public class Phase4TestServer {
    private static final Logger LOGGER = LoggerFactory.getLogger(Phase4TestServer.class);
    private static final int DEFAULT_PORT = 8080;
    private static final String DEFAULT_PATH = "/as4";
    
    public static void main(String[] args) throws Exception {
        int port = DEFAULT_PORT;
        String path = DEFAULT_PATH;
        
        // Parse command line args
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--path".equals(args[i]) && i + 1 < args.length) {
                path = args[++i];
            }
        }
        
        LOGGER.info("Starting phase4 test server on port {} at path {}", port, path);
        
        // Initialize phase4
        initializePhase4();
        
        // Create and start Jetty server
        Server server = new Server(port);
        
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);
        
        // Add AS4 servlet
        ServletHolder as4Holder = new ServletHolder("as4", new InteropAS4Servlet());
        context.addServlet(as4Holder, path);
        context.addServlet(as4Holder, path + "/*");
        
        // Start server
        server.start();
        LOGGER.info("phase4 test server started at http://localhost:{}{}", port, path);
        
        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                LOGGER.info("Shutting down phase4 test server...");
                server.stop();
            } catch (Exception e) {
                LOGGER.error("Error stopping server", e);
            }
        }));
        
        server.join();
    }
    
    private static void initializePhase4() {
        LOGGER.info("Initializing phase4...");
        
        // Initialize scopes
        WebScopeManager.onGlobalBegin(MockServletContext.create());
        
        // Initialize file IO
        File dataPath = new File("target/phase4-data");
        dataPath.mkdirs();
        WebFileIO.initPaths(dataPath, dataPath.getAbsolutePath(), false);
        
        // Initialize ID factory
        GlobalIDFactory.setPersistentIntIDFactory(new MemoryIntIDFactory());
        
        // Initialize AS4 server
        AS4ServerInitializer.initAS4Server();
        
        // Create test P-Mode for go-as4 interop
        createInteropPMode();
        
        LOGGER.info("phase4 initialized successfully");
    }
    
    private static void createInteropPMode() {
        LOGGER.info("Creating interop P-Mode...");
        
        // Create P-Mode for accepting messages from go-as4
        PMode pmode = new PMode(
            (String) null, // ID will be auto-generated
            "go-as4-interop", // initiator
            "phase4-test",    // responder
            "urn:oasis:names:tc:ebcore:partyid-type:unregistered", // agreement
            createLeg1(),
            null, // leg2 - one-way
            null, // payload profile
            null  // reception awareness
        );
        
        pmode.setMEP(com.helger.phase4.model.EMEPBinding.PUSH);
        
        // Register P-Mode
        PModeManager pmodeManager = com.helger.phase4.mgr.MetaAS4Manager.getPModeMgr();
        pmodeManager.createOrUpdatePMode(pmode);
        
        LOGGER.info("Interop P-Mode created: {}", pmode.getID());
    }
    
    private static PModeLeg createLeg1() {
        // Protocol
        PModeLegProtocol protocol = new PModeLegProtocol(
            "http://localhost:8080/as4",
            com.helger.phase4.model.ESoapVersion.SOAP_12
        );
        
        // Business info
        PModeLegBusinessInformation businessInfo = PModeLegBusinessInformation.builder()
            .setService("http://test.example.org/service")
            .setAction("TestAction")
            .build();
        
        // Security - accept RSA-SHA-256 signatures
        PModeLegSecurity security = new PModeLegSecurity();
        security.setX509SignatureAlgorithm(ECryptoAlgorithmSign.RSA_SHA_256);
        security.setX509SignatureHashFunction(ECryptoAlgorithmSignDigest.DIGEST_SHA_256);
        security.setSendReceipt(true);
        security.setSendReceiptReplyPattern(EPModeSendReceiptReplyPattern.RESPONSE);
        security.setSendReceiptNonRepudiation(true);
        
        return new PModeLeg(protocol, businessInfo, null, null, security);
    }
    
    /**
     * Custom AS4 servlet for interop testing that logs all incoming messages.
     */
    public static class InteropAS4Servlet extends AS4Servlet {
        private static final long serialVersionUID = 1L;
        private static final Logger SERVLET_LOGGER = LoggerFactory.getLogger(InteropAS4Servlet.class);
        
        @Override
        protected void onAS4Message(AS4IncomingHandler.IAS4ParsedMessage aMsg) {
            SERVLET_LOGGER.info("=== Received AS4 Message ===");
            
            if (aMsg.getUserMessage() != null) {
                var userMsg = aMsg.getUserMessage();
                SERVLET_LOGGER.info("MessageId: {}", userMsg.getEbms3UserMessage().getMessageInfo().getMessageId());
                SERVLET_LOGGER.info("From: {}", userMsg.getEbms3UserMessage().getPartyInfo().getFrom());
                SERVLET_LOGGER.info("To: {}", userMsg.getEbms3UserMessage().getPartyInfo().getTo());
                SERVLET_LOGGER.info("Service: {}", userMsg.getEbms3UserMessage().getCollaborationInfo().getService());
                SERVLET_LOGGER.info("Action: {}", userMsg.getEbms3UserMessage().getCollaborationInfo().getAction());
                SERVLET_LOGGER.info("Attachments: {}", aMsg.getAttachments().size());
            }
            
            if (aMsg.getSignalMessage() != null) {
                var signalMsg = aMsg.getSignalMessage();
                SERVLET_LOGGER.info("Signal MessageId: {}", signalMsg.getEbms3SignalMessage().getMessageInfo().getMessageId());
            }
            
            SERVLET_LOGGER.info("Signed: {}", aMsg.getState().isSoapHeaderElementProcessed());
            SERVLET_LOGGER.info("============================");
        }
    }
}
