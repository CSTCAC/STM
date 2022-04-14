FROM node:16
RUN mkdir -p ./app && chown node ./app
WORKDIR /app
COPY package*.json .

RUN npm install
RUN npm install express express-openid-connect --save

COPY --chown=node:node . .
EXPOSE 8009
CMD npm run start:dev
