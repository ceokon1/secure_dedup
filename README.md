cp .env.example .env
docker compose up --build

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 -m client_cli.main register alice@example.com
python3 -m client_cli.main login alice@example.com
python3 -m client_cli.main upload sample.jpg
python3 -m client_cli.main list-files
python3 -m client_cli.main download <file_id>
python3 -m client_cli.main delete <file_id>