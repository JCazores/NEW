#!/bin/bash

echo "Starting Laravel..."
cd "$(dirname "$0")/backend" || exit
php artisan serve &
php artisan queue:work &

echo "Starting Frontend..."
cd ../frontend || exit
npm run dev &

echo "Starting Python..."
cd ../scanner || exit
source venv/bin/activate
python app.py &

wait