#!/bin/bash
cd backend && php artisan serve &
cd ../frontend && npm run dev &
cd ../scanner && python app.py &
wait
