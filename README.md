# SimpleThreatModeller

This is my attempt at a simple Threat Modelling Tool

# How to Run
- Sign up for a free Auth0 account to manage authentication -> create an application of Web Application type for ndoejs
- rename .env.sample to .env
- Add your client ID, secret, Base URL, base issuer URL etc. to the .env file
- Ensure you have NodeJS installed, this has been developed on v16.3
- In the download directory npm install
- npm start index.js
- Navigate to Localhost port 80 (in fact you won't need to specify a port)
- Replace the 1000.csv file with the latest CAPEC 1000 download https://capec.mitre.org/data/csv/1000.csv.zip

# What it does

This app takes the CAPEC csv and with a little ham fisted mappings will output a reasonable threat model. All mapping is
performed within the index.js file and may need some more in-depth through. All database creation is managed in memory
meaning once node stops, the data is lost forever. It's not difficult to change this to a local file, it's just not
something I need right now.

All data stuff managed at the bottom of the index.js file. Table correlation is:

1) Assets Table - your list of components etc. you may find in an overall system
2) Asset to Threats - mapped using threat name not number
3) Connection table, but this is something you manually input to

Feel free to use as you like, reuse the code, heck improve on it which should be easy.

#Security
- tested using SQLMap / BURP for broken access control / SAST with Codacy / DAST with Zap

#Known issues:
- ugly UI

  
