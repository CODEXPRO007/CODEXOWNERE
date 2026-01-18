FROM php:8.2-apache

# Enable apache modules
RUN a2enmod rewrite

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql

# Copy files
COPY . /var/www/html/

# Set correct permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Apache config to allow access
RUN echo '<Directory /var/www/html>' \
    '\nAllowOverride All' \
    '\nRequire all granted' \
    '\n</Directory>' \
    > /etc/apache2/conf-enabled/render.conf

EXPOSE 80