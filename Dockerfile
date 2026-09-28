# vulnscan-demo-bad -- runs only inside a scanner's own disposable sandbox.
#
# package.json intentionally lists a package that doesn't exist on npm (for
# a "hallucinated dependency" test) plus pinned, deliberately outdated,
# vulnerable versions of express/lodash (for a CVE test). We install the two
# real packages explicitly here rather than `npm install` from the full
# manifest, so the build doesn't fail on the fake one.

FROM node:20-slim

WORKDIR /app
COPY server.js .

RUN npm install --no-save express@4.16.0 lodash@4.17.4

EXPOSE 3001
CMD ["node", "server.js"]
