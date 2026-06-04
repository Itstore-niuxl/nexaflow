FROM node:20-alpine AS build
WORKDIR /src/web
COPY web/package*.json ./
RUN npm install
COPY web ./
RUN npm run build

FROM nginx:1.27-alpine
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/web/dist /usr/share/nginx/html
EXPOSE 80

