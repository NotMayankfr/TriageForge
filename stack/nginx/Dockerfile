FROM nginx:1.25-alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/app.conf /etc/nginx/conf.d/default.conf
COPY certs/active.crt /etc/nginx/certs/active.crt
COPY certs/active.key /etc/nginx/certs/active.key

EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
