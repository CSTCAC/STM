//-------------------- Declarations ----------------------
const express = require("express");
const config = require("config");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const csv = require("csv-parser");
const fs = require("fs");
const {auth, requiresAuth} = require("express-openid-connect");

//-------------------- Configurations ----------------------
const securityHeaders = {
    "Content-Type": "text/html",
    "charset":"utf-8",
    "X-Powered-by": "",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Feature-Policy": "autoplay 'none'; camera 'none'",
    //"Content-Security-Policy": "script-src 'self' 'nonce-GwA54yjx/CUbyVkmfAzhrQ==' 'nonce-j9/wVLIhsF299f3WcoMBHg==' " + "" +
    //    "'nonce-8SDG4J06kBfDU6JO0DS/nQ==' 'nonce-H0iYXHHgq49xrOQQjSLkIw==' 'nonce-ZWgxGcitiVitzmVZOAI2eg==' https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js;"

    "Content-Security-Policy": "script-src 'self' 'nonce-GwA54yjx/CUbyVkmfAzhrQ==' 'nonce-j9/wVLIhsF299f3WcoMBHg==' 'nonce-8SDG4J06kBfDU6JO0DS/nQ==' 'nonce-H0iYXHHgq49xrOQQjSLkIw==' 'nonce-ZWgxGcitiVitzmVZOAI2eg==' https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js;" +
        "frame-ancestors 'self'; block-all-mixed-content;"+
        "default-src 'self';"+
        "style-src 'self' 'report-sample' 'unsafe-inline'  cdn.jsdelivr.net secure.gravatar.com;"+
        "object-src 'none';"+
        "frame-src 'self' widgets.wp.com;"+
        "child-src 'self';"+
        "img-src 'self' https://*.wp.com https://s.gravatar.com https://*.googleusercontent.com;"+
        "font-src 'self' data: cdn.jsdelivr.net;"+
        "connect-src 'self' *.gravatar.com cdn.jsdelivr.net https://*.googleusercontent.com;"+
        "manifest-src 'self';"+
        "base-uri 'self';"+
        "form-action 'self';"+
        "media-src 'self';"+
        "prefetch-src 'self';"+
        "worker-src 'self';"



    //"Expect-CT": "max-age=604800, enforce, report-uri="https://www.example.com/report" -- Disabled until hosted with cert
    //"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload" -- Disabled until hosted with cert
};

const configA0 = {
    authRequired: false,
    auth0Logout: true,
    secret: config.get("app.SECRET"),
    baseURL: config.get("app.BASE_URL"),
    clientID: config.get("app.CLIENT_ID"),
    issuerBaseURL: config.get("app.ISSUER_BASE_URL")
};


//-------------------- Start ----------------------
const app = express();
// Use Auth0 Config -
app.use(auth(configA0));

// Server configuration
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({extended: false})); // <--- middleware configuration

app.use(function (req, res, next) {
    res.set(securityHeaders);
    res.removeHeader("X-Powered-by");
    res.status(200);
    next();
});

app.disable("x-powered-by");

// SetDB
const db = new sqlite3.Database(":memory:");
// Starting the server
app.listen(80, () => {
    console.log("Server started (http://localhost:80/) !");
});


//-------------------- Routing ----------------------
// GET / -- this is the home page button
app.get("/", (req, res) => {
    if (req.oidc.isAuthenticated() === true) {
        res.render("index", {aBText: "Logout", aBLink: "/logout", aBPic: req.oidc.user.picture});
    } else {
        res.render("index", {aBText: "Login", aBLink: "/login", aBPic: ""});
    }
});

app.get("/profile", requiresAuth(), (req, res) => {
    if (req.oidc.isAuthenticated() === true) {
        res.render("profile", {
            aBText: "Logout",
            aBLink: "/logout",
            aBPic: req.oidc.user.picture,
            model: req.oidc.user
        });
    } else {
        res.render("profile", {aBText: "Login", aBLink: "/login", aBPic: "", model: req.oidc.user});
    }
});


app.get("/asset_types", (req, res) => {
    const sql = "SELECT * FROM Asset_Types ORDER BY AT_Name";
    db.all(sql, [], (err, rows) => {
        if (err) {
            return console.error(err.message);
        }
        if (req.oidc.isAuthenticated() === true) {
            res.render("assetTypeView", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("assetTypeView", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }
    });
});


app.get("/asset_type_threats", (req, res) => {
    const sql = "SELECT * FROM Asset_Type_Threats ORDER BY AT_Name";
    db.all(sql, [], (err, rows) => {
        if (err) {
            return console.error(err.message);
        }

        if (req.oidc.isAuthenticated() === true) {
            res.render("assetTypeThreatView", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("assetTypeThreatView", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }
    });
});


///-------------------------------------------- CONNS --------------------------------------------
// CONNECTIONS VIEW
app.get("/conn", requiresAuth(), (req, res) => {
    const sql = "SELECT * FROM CONNS where CONN_USER_NAME=? ORDER BY CONN_ID";
    db.all(sql, req.oidc.user.email, (err, rows) => {
        if (err) {
            return console.error(err.message);
        }

        if (req.oidc.isAuthenticated() === true) {
            res.render("connectionsView", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("connectionsView", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }
    });
});

//CONNECTIONS CREATE
app.get("/createConn", requiresAuth(), (req, res) => {
    const sql = "SELECT * FROM ASSET_TYPES ORDER BY AT_ID";
    db.all(sql, [], (err, rows) => {
        if (err) {
            return console.error(err.message);
        }

        if (req.oidc.isAuthenticated() === true) {
            res.render("connectionsCreate", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("connectionsCreate", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }
    });
});

app.get("/createConnFromT/:id", requiresAuth(), (req, res) => {
    const id = [req.params.id, req.oidc.user.email];
    const sql = "SELECT * FROM asset_types";
    const sql1 = "SELECT * FROM CONNS WHERE CONN_ID = ? AND CONN_USER_NAME=?";
    const obj = {};
    db.all(sql, [], (err, row) => {

        if (err) {
            return console.error(err.message);
        }

        obj.d2 = row;
        db.get(sql1, id, (err, row) => {
            obj.d1 = row;
            if (req.oidc.isAuthenticated() === true) {
                res.render("connectionsCreateFromT", {
                    aBText: "Logout",
                    aBLink: "/logout",
                    aBPic: req.oidc.user.picture,
                    model: obj.d1, model2: obj.d2
                });
            } else {
                res.render("connectionsCreateFromT", {
                    aBText: "Login",
                    aBLink: "/login",
                    aBPic: "",
                    model: obj.d1, model2: obj.d2
                });
            }
        });
    });
});

app.get("/createConnFromF/:id", requiresAuth(), (req, res) => {
    const id = [req.params.id, req.oidc.user.email];
    const sql = "SELECT * FROM asset_types";
    const sql1 = "SELECT * FROM CONNS WHERE CONN_ID = ? AND CONN_USER_NAME=?";
    const obj = {};
    db.all(sql, [], (err, row) => {
        if (err) {
            return console.error(err.message);
        }
        obj.d2 = row;
        db.get(sql1, id, (err, row) => {
            obj.d1 = row;

            if (req.oidc.isAuthenticated() === true) {
                res.render("connectionsCreateFromF", {
                    aBText: "Logout",
                    aBLink: "/logout",
                    aBPic: req.oidc.user.picture,
                    model: obj.d1, model2: obj.d2
                });
            } else {
                res.render("connectionsCreateFromF", {
                    aBText: "Login",
                    aBLink: "/login",
                    aBPic: "",
                    model: obj.d1, model2: obj.d2
                });
            }
        });
    });
});


//CONNECTIONS CREATE POST
app.post("/createConn", requiresAuth(), (req, res) => {
    const sql = "INSERT INTO CONNS (CONN_FROM,CONN_FROM_ASSET_TYPE,CONN_FROM_ZONE,CONN_PROTOCOL, CONN_TO,CONN_TO_ASSET_TYPE,CONN_TO_ZONE,Notes, CONN_USER_NAME) VALUES (?, ?, ?,?,?,?,?,?,?)";
    const newconn = [req.body.CONN_FROM, req.body.CONN_FROM_ASSET_TYPE, req.body.CONN_FROM_ZONE, req.body.CONN_PROTOCOL, req.body.CONN_TO, req.body.CONN_TO_ASSET_TYPE, req.body.CONN_TO_ZONE, req.body.Notes, req.oidc.user.email];
    db.run(sql, newconn, err => {
        if (err) {
            return console.error(err.message);
        }
        res.redirect("/conn");
    });
});

//CONNECTIONS EDIT
app.get("/editConn/:id", requiresAuth(), (req, res) => {
    const id = [req.params.id, req.oidc.user.email];
    const sql = "SELECT * FROM asset_types";
    const sql1 = "SELECT * FROM CONNS WHERE CONN_ID = ? AND CONN_USER_NAME=?";
    const obj = {};

    db.all(sql, [], (err, row) => {
        if (err) {
            return console.error(err.message);
        }
        obj.d2 = row;
        db.get(sql1, id, (err, row) => {
            obj.d1 = row;

            if (req.oidc.isAuthenticated() === true) {
                res.render("connectionsEdit", {
                    aBText: "Logout",
                    aBLink: "/logout",
                    aBPic: req.oidc.user.picture,
                    model: obj.d1, model2: obj.d2
                });
            } else {
                res.render("connectionsEdit", {
                    aBText: "Login",
                    aBLink: "/login",
                    aBPic: "",
                    model: obj.d1, model2: obj.d2
                });
            }
        });
    });
});

//////////////////////NEEDS TO PREVENT TRAVERSAL //////////////////////NEEDS TO PREVENT TRAVERSAL//////////////////////NEEDS TO PREVENT TRAVERSAL //////////////////////NEEDS TO PREVENT TRAVERSAL //////////////////////NEEDS TO PREVENT TRAVERSAL
//CONNECTIONS EDIT POST
app.post("/editConn/:id", requiresAuth(), (req, res) => {
    const id = req.params.id;
    const sql = "UPDATE CONNS SET CONN_FROM =?       ,CONN_FROM_ASSET_TYPE=?,       CONN_FROM_ZONE=?,       CONN_PROTOCOL=?,       CONN_TO=?,        CONN_TO_ASSET_TYPE=?,   CONN_TO_ZONE=?,          Notes=? WHERE CONN_ID=? AND CONN_USER_NAME=?";
    const conn = [req.body.CONN_FROM, req.body.CONN_FROM_ASSET_TYPE, req.body.CONN_FROM_ZONE, req.body.CONN_PROTOCOL, req.body.CONN_TO, req.body.CONN_TO_ASSET_TYPE, req.body.CONN_TO_ZONE, req.body.Notes, id, req.oidc.user.email];
    db.run(sql, conn, err => {
        if (err) {
            return console.error(err.message);
        }
        res.redirect("/conn");
    });
});


app.get("/threatGraph", requiresAuth(), (req, res) => {
    const sql = "SELECT REPLACE(c.CONN_FROM,' ','_') as CONN_FROM, REPLACE(c.CONN_PROTOCOL,' ','_') as CONN_PROTOCOL, REPLACE(c.CONN_TO,' ','_') as CONN_TO FROM CONNS c where CONN_USER_NAME=? ORDER BY CONN_ID ";
    db.all(sql, req.oidc.user.email, (err, rows) => {
        if (err) {
            return console.error(err.message);
        }

        if (req.oidc.isAuthenticated() === true) {
            res.render("threatModelVisual", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("threatModelVisual", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }
    });
});


//CONNECTIONS DELETE
app.get("/deleteConn/:id", requiresAuth(), (req, res) => {
    const id = [req.params.id,req.oidc.user.email];
    const sql = "SELECT * FROM CONNS WHERE CONN_ID = ? and CONN_USER_NAME=?";
    db.get(sql, id, (err, rows) => {
        if (err) {
            return console.error(err.message);
        }

        if (req.oidc.isAuthenticated() === true) {
            res.render("connectionsDelete", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("connectionsDelete", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }
    });
});

//CONNECTIONS DELETE POST
app.post("/deleteConn/:id", requiresAuth(), (req, res) => {
    const id = [req.params.id,req.oidc.user.email];
    const sql = "DELETE FROM CONNS WHERE CONN_ID = ? and CONN_USER_NAME=?";
    db.run(sql, id, err => {
        if (err) {
            return console.error(err.message);
        }
        res.redirect("/conn");
    });
});

app.get("/threatmodel", requiresAuth(), (req, res) => {
    const sql = "select distinct * from (select c.CONN_FROM as Asset, c.CONN_FROM_ASSET_TYPE as Asset_Type, a.AT_Threat, t.Description, " +
        "t.Alternate_Terms, t.Likelihood_Of_Attack, t.Typical_Severity, REPLACE(t.Mitigations,'::', '-') as NewMit, c.CONN_USER_NAME " +
        "FROM CONNS c left join ASSET_TYPE_THREATS a on c.CONN_FROM_ASSET_TYPE = a.AT_NAME left join capec t on a.AT_Threat=t.Name where c.CONN_USER_NAME=?" +
        "union all " +
        "SELECT c.CONN_TO as Asset, c.CONN_TO_ASSET_TYPE as Asset_Type, a.AT_Threat, t.Description, " +
        "t.Alternate_Terms, t.Likelihood_Of_Attack, t.Typical_Severity, REPLACE(t.Mitigations,'::', '-') as NewMit, c.CONN_USER_NAME " +
        "FROM CONNS c left join ASSET_TYPE_THREATS a on c.CONN_TO_ASSET_TYPE = a.AT_NAME left join capec t on a.AT_Threat=t.Name  where c.CONN_USER_NAME=?)";

    db.all(sql, req.oidc.user.email, (err, rows) => {
        if (err) {
            return console.error(err.message);
        }

        if (req.oidc.isAuthenticated() === true) {
            res.render("threatModelView", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("threatModelView", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }
    });
});

app.get("/capecDisplay/:name", requiresAuth(), (req, res) => {
    const id = req.params.name;
    const sql = "SELECT * FROM Capec c WHERE c.name = ? ";
    db.get(sql, id, (err, rows) => {
        if (err) {
            return console.error(err.message);
        }

        if (req.oidc.isAuthenticated() === true) {
            res.render("capecView", {
                aBText: "Logout",
                aBLink: "/logout",
                aBPic: req.oidc.user.picture,
                model: rows
            });
        } else {
            res.render("capecView", {
                aBText: "Login",
                aBLink: "/login",
                aBPic: "",
                model: rows
            });
        }

    });
});


///-------------------------------------------- TABLES ------------------------------------------
const sql_asset_types = `CREATE TABLE IF NOT EXISTS Asset_Types (
  AT_ID INTEGER PRIMARY KEY AUTOINCREMENT,
  AT_NAME VARCHAR(100) NOT NULL,
  Comments TEXT
);`;
//needs lookups from asset types and capec
const sql_asset_threats = `CREATE TABLE IF NOT EXISTS Asset_Type_Threats (
  ATT_ID INTEGER PRIMARY KEY AUTOINCREMENT,
  AT_NAME VARCHAR(100) NOT NULL, 
  AT_Threat VARCHAR(100) NOT NULL, 
  Comments TEXT
);`;
//needs lookups from asset types and capec
const sql_capec = `CREATE TABLE IF NOT EXISTS Capec (
  C_ID TEXT,
  Name VARCHAR(100), 
  Abstraction TEXT,
  Status TEXT, 
  Description TEXT, 
  Alternate_Terms TEXT, 
  Likelihood_Of_Attack TEXT, 
  Typical_Severity TEXT, 
  Related_Attack_Patterns TEXT, 
  Execution_Flow TEXT, 
  Prerequisites TEXT, 
  Skills_Required TEXT, 
  Resources_Required TEXT,
  Indicators TEXT,
  Consequences TEXT,
  Mitigations TEXT,
  Example_Instances TEXT,
  Related_Weaknesses TEXT,
  Taxonomy_Mappings TEXT,
  Notes TEXT
);`;

const sql_conns = `CREATE TABLE IF NOT EXISTS CONNS (
  CONN_ID INTEGER PRIMARY KEY AUTOINCREMENT,
  CONN_USER_NAME varchar(100),
  CONN_FROM VARCHAR(100), 
  CONN_FROM_ASSET_TYPE TEXT,
  CONN_FROM_ZONE TEXT,
  CONN_PROTOCOL TEXT,
  CONN_TO VARCHAR(100),
  CONN_TO_ASSET_TYPE TEXT,
  CONN_TO_ZONE TEXT,
  Notes TEXT
);`;

const sql_insert_asset_types = `INSERT INTO Asset_Types (AT_Name, Comments) VALUES
  ('API Gateway', 'API gateway either cloud or locally hosted, includes any middleware e.g. Java Runtime and Operating Systems'),
  ('Authentication Server', 'Authentication Server providing LDAP, Kerberos, SAML, OIDC, OAUTH2, or just basic authentication'),
  ('Internal User', 'A user internal to a company'),
  ('External User', 'A user external to a company who consumes internal resources'),
  ('Database Server', 'SQL Server, Oracle, MySQL, PostgreSQL etc.'),
  ('DDOS Protection', 'Dedicated DDOS protection e.g. Cloudflare, Akamai etc.'),
  ('Email Client', 'Either cloud based mail provider or Mail client.'),
  ('Executable Binary', 'Native installable or executable application running on the OS e.g. MS Word'),
  ('Flash Application', 'Application writted in Adobe/Shockwave Flash'),
  ('Load Balancer', 'Load Balancer'),
  ('Proxy / Reverse Proxy', 'Web Proxy'),
  ('Message Queue', 'IBM MQ, Rabbit MQ, Apache MQ etc.'),
  ('Microservice / API / Webhook', 'Microservice, API or Webhook'),
  ('Multicast', 'E.g. Chromecast or other type services'),
  ('Network Devices', 'E.g. Firewalls, DLP Controls, TLS Inspection, IPS, IDS'),
  ('Network Services', 'Network appliances providing services such as DNS, DHCP, PKI, CRL, OCSP etc.'),
  ('Network Share / Local Disk', 'Storage medium'),
  ('SOAP Parser / API', 'Application or component parsing SOAP message format'),
  ('Static Web Page', 'Webpages with no application locic'),
  ('WAF', 'Web Appliation Firewall'),
  ('Web Application', 'includes any middleware e.g. Java Runtime and Operating Systems'),
  ('Web Browser', 'Can be internal or external user browser');`;

// Libraries + Source Code apply to all

const sql_insert_asset_threats = `INSERT INTO Asset_Type_Threats (AT_Name, AT_Threat) VALUES
('API Gateway','XML Schema Poisoning'),
('API Gateway','XML Ping of the Death'),
('SOAP Parser / API','XML Schema Poisoning'),
('SOAP Parser / API','XML Ping of the Death'),
('Microservice / API / Webhook','XML Schema Poisoning'),
('Microservice / API / Webhook','XML Ping of the Death'),
('Web Application','XML Schema Poisoning'),
('Web Application','XML Ping of the Death'),
('Web Application','SQL Injection through SOAP Parameter Tampering'),
('Web Application','Format String Injection'),
('Web Application','Reflection Injection'),
('Web Application','Relative Path Traversal'),
('Web Application','Detect Unpublicized Web Pages'),
('Web Application','Detect Unpublicized Web Services'),
('Web Application','Checksum Spoofing'),
('Web Application','Redirect Access to Libraries'),
('Web Application','Web Application Fingerprinting'),
('Web Application','Flash Parameter Injection'),
('Web Application','XSS Targeting Non-Script Elements'),
('Web Application','Black Box Reverse Engineering'),
('Web Application','Embedding Scripts within Scripts'),
('Web Application','PHP Remote File Inclusion'),
('Web Application','Session Credential Falsification through Forging'),
('Web Application','Exponential Data Expansion'),
('Web Application','XSS Targeting Error Pages'),
('Web Application','XSS Using Alternate Syntax'),
('Web Application','Removal of filters: Input filters, output filters, data masking'),
('Web Application','Serialized Data External Linking'),
('Web Application','Harvesting Information via API Event Monitoring'),
('Web Application','Application API Message Manipulation via Man-in-the-Middle'),
('Web Application','Transaction or Event Tampering via Application API Manipulation'),
('Web Application','Application API Navigation Remapping'),
('Web Application','Application API Button Hijacking'),
('Web Application','Content Spoofing Via Application API Manipulation'),
('Web Application','Web Services API Signature Forgery Leveraging Hash Function Extension Weakness'),
('Web Application','Buffer Overflow in an API Call'),
('Microservice / API / Webhook','SQL Injection through SOAP Parameter Tampering'),
('Microservice / API / Webhook','Format String Injection'),
('Microservice / API / Webhook','Reflection Injection'),
('Microservice / API / Webhook','Relative Path Traversal'),
('Microservice / API / Webhook','Checksum Spoofing'),
('Microservice / API / Webhook','Redirect Access to Libraries'),
('Microservice / API / Webhook','Web Application Fingerprinting'),
('Microservice / API / Webhook','Black Box Reverse Engineering'),
('Microservice / API / Webhook','Session Credential Falsification through Forging'),
('Microservice / API / Webhook','Exponential Data Expansion'),
('Microservice / API / Webhook','Removal of filters: Input filters, output filters, data masking'),
('Microservice / API / Webhook','Serialized Data External Linking'),
('Microservice / API / Webhook','Web Services API Signature Forgery Leveraging Hash Function Extension Weakness'),
('Microservice / API / Webhook','Buffer Overflow in an API Call'),
('Database Server','SQL Injection through SOAP Parameter Tampering'),
('Message Queue','SQL Injection through SOAP Parameter Tampering'),
('SOAP Parser / API','SQL Injection through SOAP Parameter Tampering'),
('Microservice / API / Webhook','Accessing Functionality Not Properly Constrained by ACLs'),
('Microservice / API / Webhook','Buffer Overflow via Environment Variables'),
('Microservice / API / Webhook','Overflow Buffers'),
('Microservice / API / Webhook','Server Side Include (SSI) Injection'),
('Microservice / API / Webhook','Session Sidejacking'),
('Microservice / API / Webhook','JSON Hijacking (aka JavaScript Hijacking)'),
('Microservice / API / Webhook','Double Encoding'),
('Microservice / API / Webhook','Path Traversal'),
('Microservice / API / Webhook','Directory Indexing'),
('Microservice / API / Webhook','Symlink Attack'),
('Web Application','Accessing Functionality Not Properly Constrained by ACLs'),
('Web Application','Buffer Overflow via Environment Variables'),
('Web Application','Overflow Buffers'),
('Web Application','Server Side Include (SSI) Injection'),
('Web Application','Session Sidejacking'),
('Web Application','JSON Hijacking (aka JavaScript Hijacking)'),
('Web Application','Double Encoding'),
('Web Application','Path Traversal'),
('Web Application','Directory Indexing'),
('Web Application','Symlink Attack'),
('Web Application','Manipulating Hidden Fields'),
('Database Server','Accessing Functionality Not Properly Constrained by ACLs'),
('Network Share / Local Disk','Accessing Functionality Not Properly Constrained by ACLs'),
('Web Browser','Clickjacking'),
('Web Browser','Cross Zone Scripting'),
('Web Browser','Cross Site Tracing'),
('Web Browser','Cache Poisoning'),
('Web Browser','Spear Phishing'),
('Web Browser','Mobile Phishing'),
('Web Browser','Malicious Software Download'),
('Network Services','Cache Poisoning'),
('Email Client','Spear Phishing'),
('Email Client','Mobile Phishing'),
('API Gateway','Malicious Software Download'),
('Authentication Server','Malicious Software Download'),
('Internal User','Malicious Software Download'),
('External User','Malicious Software Download'),
('Database Server','Malicious Software Download'),
('DDOS Protection','Malicious Software Download'),
('Email Client','Malicious Software Download'),
('Executable Binary','Malicious Software Download'),
('Flash Application','Malicious Software Download'),
('Load Balancer','Malicious Software Download'),
('Proxy / Reverse Proxy','Malicious Software Download'),
('Message Queue','Malicious Software Download'),
('Microservice / API / Webhook','Malicious Software Download'),
('Multicast','Malicious Software Download'),
('Network Devices','Malicious Software Download'),
('Network Services','Malicious Software Download'),
('Network Share / Local Disk','Malicious Software Download'),
('SOAP Parser / API','Malicious Software Download'),
('Static Web Page','Malicious Software Download'),
('WAF','Malicious Software Download'),
('Web Application','Malicious Software Download'),
('Web Browser','Malicious Software Download'),
('Web Application','Cross Site Tracing'),
('Microservice / API / Webhook','Cross Site Tracing'),
('Database Server','Command Line Execution through SQL Injection'),
('Database Server','Object Relational Mapping Injection'),
('Database Server','Command Delimiters'),
('Database Server','Expanding Control over the Operating System from the Database'),
('Database Server','SQL Injection'),
('Database Server','NoSQL Injection'),
('Database Server','Blind SQL Injection'),
('Executable Binary','Format String Injection'),
('Executable Binary','Reflection Injection'),
('Executable Binary','Relative Path Traversal'),
('Executable Binary','Client-side Injection-induced Buffer Overflow'),
('Executable Binary','Checksum Spoofing'),
('Executable Binary','Reverse Engineer an Executable to Expose Assumed Hidden Functionality'),
('Executable Binary','Read Sensitive Constants Within an Executable'),
('Executable Binary','Session Credential Falsification through Forging'),
('Executable Binary','Removing Important Client Functionality'),
('API Gateway','Exploit Non-Production Interfaces'),
('Authentication Server','Exploit Non-Production Interfaces'),
('Internal User','Exploit Non-Production Interfaces'),
('External User','Exploit Non-Production Interfaces'),
('Database Server','Exploit Non-Production Interfaces'),
('DDOS Protection','Exploit Non-Production Interfaces'),
('Email Client','Exploit Non-Production Interfaces'),
('Executable Binary','Exploit Non-Production Interfaces'),
('Flash Application','Exploit Non-Production Interfaces'),
('Load Balancer','Exploit Non-Production Interfaces'),
('Proxy / Reverse Proxy','Exploit Non-Production Interfaces'),
('Message Queue','Exploit Non-Production Interfaces'),
('Microservice / API / Webhook','Exploit Non-Production Interfaces'),
('Multicast','Exploit Non-Production Interfaces'),
('Network Devices','Exploit Non-Production Interfaces'),
('Network Services','Exploit Non-Production Interfaces'),
('Network Share / Local Disk','Exploit Non-Production Interfaces'),
('SOAP Parser / API','Exploit Non-Production Interfaces'),
('Static Web Page','Exploit Non-Production Interfaces'),
('WAF','Exploit Non-Production Interfaces'),
('Web Application','Exploit Non-Production Interfaces'),
('Web Browser','Exploit Non-Production Interfaces'),
('API Gateway','Subverting Environment Variable Values'),
('Authentication Server','Subverting Environment Variable Values'),
('Internal User','Subverting Environment Variable Values'),
('External User','Subverting Environment Variable Values'),
('Database Server','Subverting Environment Variable Values'),
('DDOS Protection','Subverting Environment Variable Values'),
('Email Client','Subverting Environment Variable Values'),
('Executable Binary','Subverting Environment Variable Values'),
('Flash Application','Subverting Environment Variable Values'),
('Load Balancer','Subverting Environment Variable Values'),
('Proxy / Reverse Proxy','Subverting Environment Variable Values'),
('Message Queue','Subverting Environment Variable Values'),
('Microservice / API / Webhook','Subverting Environment Variable Values'),
('Multicast','Subverting Environment Variable Values'),
('Network Devices','Subverting Environment Variable Values'),
('Network Services','Subverting Environment Variable Values'),
('Network Share / Local Disk','Subverting Environment Variable Values'),
('SOAP Parser / API','Subverting Environment Variable Values'),
('Static Web Page','Subverting Environment Variable Values'),
('WAF','Subverting Environment Variable Values'),
('Web Application','Subverting Environment Variable Values'),
('Web Browser','Subverting Environment Variable Values'),
('API Gateway','Sniffing Attacks'),
('Authentication Server','Sniffing Attacks'),
('Internal User','Sniffing Attacks'),
('External User','Sniffing Attacks'),
('Database Server','Sniffing Attacks'),
('DDOS Protection','Sniffing Attacks'),
('Email Client','Sniffing Attacks'),
('Executable Binary','Sniffing Attacks'),
('Flash Application','Sniffing Attacks'),
('Load Balancer','Sniffing Attacks'),
('Proxy / Reverse Proxy','Sniffing Attacks'),
('Message Queue','Sniffing Attacks'),
('Microservice / API / Webhook','Sniffing Attacks'),
('Multicast','Sniffing Attacks'),
('Network Devices','Sniffing Attacks'),
('Network Services','Sniffing Attacks'),
('Network Share / Local Disk','Sniffing Attacks'),
('SOAP Parser / API','Sniffing Attacks'),
('Static Web Page','Sniffing Attacks'),
('WAF','Sniffing Attacks'),
('Web Application','Sniffing Attacks'),
('Web Browser','Sniffing Attacks'),
('API Gateway','Sniffing Network Traffic'),
('Authentication Server','Sniffing Network Traffic'),
('Internal User','Sniffing Network Traffic'),
('External User','Sniffing Network Traffic'),
('Database Server','Sniffing Network Traffic'),
('DDOS Protection','Sniffing Network Traffic'),
('Email Client','Sniffing Network Traffic'),
('Executable Binary','Sniffing Network Traffic'),
('Flash Application','Sniffing Network Traffic'),
('Load Balancer','Sniffing Network Traffic'),
('Proxy / Reverse Proxy','Sniffing Network Traffic'),
('Message Queue','Sniffing Network Traffic'),
('Microservice / API / Webhook','Sniffing Network Traffic'),
('Multicast','Sniffing Network Traffic'),
('Network Devices','Sniffing Network Traffic'),
('Network Services','Sniffing Network Traffic'),
('Network Share / Local Disk','Sniffing Network Traffic'),
('SOAP Parser / API','Sniffing Network Traffic'),
('Static Web Page','Sniffing Network Traffic'),
('WAF','Sniffing Network Traffic'),
('Web Application','Sniffing Network Traffic'),
('Web Browser','Sniffing Network Traffic'),
('API Gateway','White Box Reverse Engineering'),
('Authentication Server','White Box Reverse Engineering'),
('Internal User','White Box Reverse Engineering'),
('External User','White Box Reverse Engineering'),
('Database Server','White Box Reverse Engineering'),
('DDOS Protection','White Box Reverse Engineering'),
('Email Client','White Box Reverse Engineering'),
('Executable Binary','White Box Reverse Engineering'),
('Flash Application','White Box Reverse Engineering'),
('Load Balancer','White Box Reverse Engineering'),
('Proxy / Reverse Proxy','White Box Reverse Engineering'),
('Message Queue','White Box Reverse Engineering'),
('Microservice / API / Webhook','White Box Reverse Engineering'),
('Multicast','White Box Reverse Engineering'),
('Network Devices','White Box Reverse Engineering'),
('Network Services','White Box Reverse Engineering'),
('Network Share / Local Disk','White Box Reverse Engineering'),
('SOAP Parser / API','White Box Reverse Engineering'),
('Static Web Page','White Box Reverse Engineering'),
('WAF','White Box Reverse Engineering'),
('Web Application','White Box Reverse Engineering'),
('Web Browser','White Box Reverse Engineering'),
('API Gateway','Exploiting Incorrectly Configured Access Control Security Levels'),
('Authentication Server','Exploiting Incorrectly Configured Access Control Security Levels'),
('Internal User','Exploiting Incorrectly Configured Access Control Security Levels'),
('External User','Exploiting Incorrectly Configured Access Control Security Levels'),
('Database Server','Exploiting Incorrectly Configured Access Control Security Levels'),
('DDOS Protection','Exploiting Incorrectly Configured Access Control Security Levels'),
('Email Client','Exploiting Incorrectly Configured Access Control Security Levels'),
('Executable Binary','Exploiting Incorrectly Configured Access Control Security Levels'),
('Flash Application','Exploiting Incorrectly Configured Access Control Security Levels'),
('Load Balancer','Exploiting Incorrectly Configured Access Control Security Levels'),
('Proxy / Reverse Proxy','Exploiting Incorrectly Configured Access Control Security Levels'),
('Message Queue','Exploiting Incorrectly Configured Access Control Security Levels'),
('Microservice / API / Webhook','Exploiting Incorrectly Configured Access Control Security Levels'),
('Multicast','Exploiting Incorrectly Configured Access Control Security Levels'),
('Network Devices','Exploiting Incorrectly Configured Access Control Security Levels'),
('Network Services','Exploiting Incorrectly Configured Access Control Security Levels'),
('Network Share / Local Disk','Exploiting Incorrectly Configured Access Control Security Levels'),
('SOAP Parser / API','Exploiting Incorrectly Configured Access Control Security Levels'),
('Static Web Page','Exploiting Incorrectly Configured Access Control Security Levels'),
('WAF','Exploiting Incorrectly Configured Access Control Security Levels'),
('Web Application','Exploiting Incorrectly Configured Access Control Security Levels'),
('Web Browser','Exploiting Incorrectly Configured Access Control Security Levels'),
('API Gateway','Malicious Software Update'),
('Authentication Server','Malicious Software Update'),
('Internal User','Malicious Software Update'),
('External User','Malicious Software Update'),
('Database Server','Malicious Software Update'),
('DDOS Protection','Malicious Software Update'),
('Email Client','Malicious Software Update'),
('Executable Binary','Malicious Software Update'),
('Flash Application','Malicious Software Update'),
('Load Balancer','Malicious Software Update'),
('Proxy / Reverse Proxy','Malicious Software Update'),
('Message Queue','Malicious Software Update'),
('Microservice / API / Webhook','Malicious Software Update'),
('Multicast','Malicious Software Update'),
('Network Devices','Malicious Software Update'),
('Network Services','Malicious Software Update'),
('Network Share / Local Disk','Malicious Software Update'),
('SOAP Parser / API','Malicious Software Update'),
('Static Web Page','Malicious Software Update'),
('WAF','Malicious Software Update'),
('Web Application','Malicious Software Update'),
('Web Browser','Malicious Software Update'),
('API Gateway','Malicious Automated Software Update via Redirection'),
('Authentication Server','Malicious Automated Software Update via Redirection'),
('Internal User','Malicious Automated Software Update via Redirection'),
('External User','Malicious Automated Software Update via Redirection'),
('Database Server','Malicious Automated Software Update via Redirection'),
('DDOS Protection','Malicious Automated Software Update via Redirection'),
('Email Client','Malicious Automated Software Update via Redirection'),
('Executable Binary','Malicious Automated Software Update via Redirection'),
('Flash Application','Malicious Automated Software Update via Redirection'),
('Load Balancer','Malicious Automated Software Update via Redirection'),
('Proxy / Reverse Proxy','Malicious Automated Software Update via Redirection'),
('Message Queue','Malicious Automated Software Update via Redirection'),
('Microservice / API / Webhook','Malicious Automated Software Update via Redirection'),
('Multicast','Malicious Automated Software Update via Redirection'),
('Network Devices','Malicious Automated Software Update via Redirection'),
('Network Services','Malicious Automated Software Update via Redirection'),
('Network Share / Local Disk','Malicious Automated Software Update via Redirection'),
('SOAP Parser / API','Malicious Automated Software Update via Redirection'),
('Static Web Page','Malicious Automated Software Update via Redirection'),
('WAF','Malicious Automated Software Update via Redirection'),
('Web Application','Malicious Automated Software Update via Redirection'),
('Web Browser','Malicious Automated Software Update via Redirection'),
('API Gateway','Fake the Source of Data'),
('Authentication Server','Fake the Source of Data'),
('Internal User','Fake the Source of Data'),
('External User','Fake the Source of Data'),
('Database Server','Fake the Source of Data'),
('DDOS Protection','Fake the Source of Data'),
('Email Client','Fake the Source of Data'),
('Executable Binary','Fake the Source of Data'),
('Flash Application','Fake the Source of Data'),
('Load Balancer','Fake the Source of Data'),
('Proxy / Reverse Proxy','Fake the Source of Data'),
('Message Queue','Fake the Source of Data'),
('Microservice / API / Webhook','Fake the Source of Data'),
('Multicast','Fake the Source of Data'),
('Network Devices','Fake the Source of Data'),
('Network Services','Fake the Source of Data'),
('Network Share / Local Disk','Fake the Source of Data'),
('SOAP Parser / API','Fake the Source of Data'),
('Static Web Page','Fake the Source of Data'),
('WAF','Fake the Source of Data'),
('Web Application','Fake the Source of Data'),
('Web Browser','Fake the Source of Data'),
('API Gateway','Encryption Brute Forcing'),
('Authentication Server','Encryption Brute Forcing'),
('Internal User','Encryption Brute Forcing'),
('External User','Encryption Brute Forcing'),
('Database Server','Encryption Brute Forcing'),
('DDOS Protection','Encryption Brute Forcing'),
('Email Client','Encryption Brute Forcing'),
('Executable Binary','Encryption Brute Forcing'),
('Flash Application','Encryption Brute Forcing'),
('Load Balancer','Encryption Brute Forcing'),
('Proxy / Reverse Proxy','Encryption Brute Forcing'),
('Message Queue','Encryption Brute Forcing'),
('Microservice / API / Webhook','Encryption Brute Forcing'),
('Multicast','Encryption Brute Forcing'),
('Network Devices','Encryption Brute Forcing'),
('Network Services','Encryption Brute Forcing'),
('Network Share / Local Disk','Encryption Brute Forcing'),
('SOAP Parser / API','Encryption Brute Forcing'),
('Static Web Page','Encryption Brute Forcing'),
('WAF','Encryption Brute Forcing'),
('Web Application','Encryption Brute Forcing'),
('Web Browser','Encryption Brute Forcing'),
('API Gateway','Manipulate Registry Information'),
('Authentication Server','Manipulate Registry Information'),
('Internal User','Manipulate Registry Information'),
('External User','Manipulate Registry Information'),
('Database Server','Manipulate Registry Information'),
('DDOS Protection','Manipulate Registry Information'),
('Email Client','Manipulate Registry Information'),
('Executable Binary','Manipulate Registry Information'),
('Flash Application','Manipulate Registry Information'),
('Load Balancer','Manipulate Registry Information'),
('Proxy / Reverse Proxy','Manipulate Registry Information'),
('Message Queue','Manipulate Registry Information'),
('Microservice / API / Webhook','Manipulate Registry Information'),
('Multicast','Manipulate Registry Information'),
('Network Devices','Manipulate Registry Information'),
('Network Services','Manipulate Registry Information'),
('Network Share / Local Disk','Manipulate Registry Information'),
('SOAP Parser / API','Manipulate Registry Information'),
('Static Web Page','Manipulate Registry Information'),
('WAF','Manipulate Registry Information'),
('Web Application','Manipulate Registry Information'),
('Web Browser','Manipulate Registry Information'),
('API Gateway','Lifting Sensitive Data Embedded in Cache'),
('Authentication Server','Lifting Sensitive Data Embedded in Cache'),
('Internal User','Lifting Sensitive Data Embedded in Cache'),
('External User','Lifting Sensitive Data Embedded in Cache'),
('Database Server','Lifting Sensitive Data Embedded in Cache'),
('DDOS Protection','Lifting Sensitive Data Embedded in Cache'),
('Email Client','Lifting Sensitive Data Embedded in Cache'),
('Executable Binary','Lifting Sensitive Data Embedded in Cache'),
('Flash Application','Lifting Sensitive Data Embedded in Cache'),
('Load Balancer','Lifting Sensitive Data Embedded in Cache'),
('Proxy / Reverse Proxy','Lifting Sensitive Data Embedded in Cache'),
('Message Queue','Lifting Sensitive Data Embedded in Cache'),
('Microservice / API / Webhook','Lifting Sensitive Data Embedded in Cache'),
('Multicast','Lifting Sensitive Data Embedded in Cache'),
('Network Devices','Lifting Sensitive Data Embedded in Cache'),
('Network Services','Lifting Sensitive Data Embedded in Cache'),
('Network Share / Local Disk','Lifting Sensitive Data Embedded in Cache'),
('SOAP Parser / API','Lifting Sensitive Data Embedded in Cache'),
('Static Web Page','Lifting Sensitive Data Embedded in Cache'),
('WAF','Lifting Sensitive Data Embedded in Cache'),
('Web Application','Lifting Sensitive Data Embedded in Cache'),
('Web Browser','Lifting Sensitive Data Embedded in Cache'),
('API Gateway','Signing Malicious Code'),
('Authentication Server','Signing Malicious Code'),
('Internal User','Signing Malicious Code'),
('External User','Signing Malicious Code'),
('Database Server','Signing Malicious Code'),
('DDOS Protection','Signing Malicious Code'),
('Email Client','Signing Malicious Code'),
('Executable Binary','Signing Malicious Code'),
('Flash Application','Signing Malicious Code'),
('Load Balancer','Signing Malicious Code'),
('Proxy / Reverse Proxy','Signing Malicious Code'),
('Message Queue','Signing Malicious Code'),
('Microservice / API / Webhook','Signing Malicious Code'),
('Multicast','Signing Malicious Code'),
('Network Devices','Signing Malicious Code'),
('Network Services','Signing Malicious Code'),
('Network Share / Local Disk','Signing Malicious Code'),
('SOAP Parser / API','Signing Malicious Code'),
('Static Web Page','Signing Malicious Code'),
('WAF','Signing Malicious Code'),
('Web Application','Signing Malicious Code'),
('Web Browser','Signing Malicious Code'),
('Microservice / API / Webhook','HTTP Request Splitting'),
('Web Application','HTTP Request Splitting'),
('Microservice / API / Webhook','Cause Web Server Misclassification'),
('Web Application','Cause Web Server Misclassification'),
('Load Balancer','HTTP Request Splitting'),
('Proxy / Reverse Proxy','HTTP Request Splitting'),
('WAF','HTTP Request Splitting'),
('Multicast','Choosing Message Identifier'),
('Executable Binary','Try All Common Switches'),
('Email Client','Email Injection'),
('Email Client','Create Malicious Client'),
('Web Application','Serialized Data External Linking'),
('SOAP Parser / API','Serialized Data External Linking'),
('Executable Binary','Removal of filters: Input filters, output filters, data masking'),
('Executable Binary','Black Box Reverse Engineering'),
('Email Client','IMAP/SMTP Command Injection'),
('Web Browser','Flash File Overlay'),
('Microservice / API / Webhook','Exploit Script-Based APIs'),
('Microservice / API / Webhook','Calling Micro-Services Directly'),
('Authentication Server','LDAP Injection'),
('Authentication Server','Dictionary-based Password Attack'),
('Authentication Server','Inducing Account Lockout'),
('Network Services','DNS Cache Poisoning'),
('Executable Binary','Redirect Access to Libraries'),
('Microservice / API / Webhook','Redirect Access to Libraries'),
('SOAP Parser / API','Redirect Access to Libraries'),
('Web Application','Redirect Access to Libraries'),
('Flash Application','Cross-Site Flashing'),
('Flash Application','Flash Injection'),
('SOAP Parser / API','Exponential Data Expansion'),

 
 
 
  ('Browser', 'everything');`;

db.serialize(function () {
    try {
        db.run(sql_asset_types);
        db.run(sql_insert_asset_types);
        db.run(sql_asset_threats);
        db.run(sql_insert_asset_threats);
        db.run(sql_conns);
        db.run(sql_capec);

        const sql_insert_capec = db.prepare(`INSERT INTO Capec (C_ID,Name,Abstraction ,Status ,Description ,Alternate_Terms ,Likelihood_Of_Attack ,Typical_Severity ,Related_Attack_Patterns ,Execution_Flow ,Prerequisites ,Skills_Required,Resources_Required,Indicators,Consequences,Mitigations,Example_Instances,Related_Weaknesses,Taxonomy_Mappings ,Notes) VALUES
   (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);`);

        fs.createReadStream("./data/1000.csv")
            .pipe(csv({"separator": ","}))
            .on("data", (row) => {
                const c1 = row["ID"];
                const c2 = row["Name"];
                const c3 = row["Abstraction"];
                const c4 = row["Status"];
                const c5 = row["Description"];
                const c6 = row["Alternate Terms"];
                const c7 = row["Likelihood Of Attack"];
                const c8 = row["Typical Severity"];
                const c9 = row["Related Attack Patterns"];
                const c10 = row["Execution Flow"];
                const c11 = row["Prerequisites"];
                const c12 = row["Skills Required"];
                const c13 = row["Resources Required"];
                const c14 = row["Indicators"];
                const c15 = row["Consequences"];
                const c16 = row["Mitigations"];
                const c17 = row["Example Instances"];
                const c18 = row["Related Weaknesses"];
                const c19 = row["Taxonomy Mappings"];
                const c20 = row["Notes"];

                const c6a = "--" + c6.substring(2, c6.length - 2).replaceAll("::", "\n--");
                const c10a = "--" + c10.substring(2, c10.length - 2).replaceAll("::", "\n--");
                const c11a = "--" + c11.substring(2, c11.length - 2).replaceAll("::", "\n--");
                const c12a = "--" + c12.substring(2, c12.length - 2).replaceAll("::", "\n--");
                const c13a = "--" + c13.substring(2, c13.length - 2).replaceAll("::", "\n--");
                const c14a = "--" + c14.substring(2, c14.length - 2).replaceAll("::", "\n--");
                const c15a = "--" + c15.substring(2, c15.length - 2).replaceAll("::", "\n--");
                const c16a = "--" + c16.substring(2, c16.length - 2).replaceAll("::", "\n--");
                const c17a = "--" + c17.substring(2, c17.length - 2).replaceAll("::", "\n--");
                const c19a = "--" + c19.substring(2, c19.length - 2).replaceAll("::", "\n--");
                const c20a = "--" + c20.substring(2, c20.length - 2).replaceAll("::", "\n--");

                sql_insert_capec.run(c1, c2, c3, c4, c5, c6a, c7, c8, c9, c10a, c11a, c12a, c13a, c14a, c15a, c16a, c17a, c18, c19a, c20a);
                //console.log(row);
                //                console.log(row.Name)
            })
            .on("end", () => {
                console.log('CSV file successfully processed');
            });

        //db.run(sql_insert_capec(row.ID, row.NAME));
    } catch (e) {
        console.log(e);
    }
});


// ----------------------------------------- 404 and 500 error handling -----------------------------------------
// Handle 404 error messages
app.use(function (req, res) {
    if (req.oidc.isAuthenticated() === true) {
        res.render("error400", {
            aBText: "Logout",
            aBLink: "/logout",
            aBPic: req.oidc.user.picture,
        });
    } else {
        res.render("error400", {
            aBText: "Login",
            aBLink: "/login",
            aBPic: "",
        });
    }
});

//Handle error 500 messages
app.use(function (error, req, res) {
    res.send("Something went wrong with this request");
});
// ----------------------------------------- --------------------------------------------------------------------
