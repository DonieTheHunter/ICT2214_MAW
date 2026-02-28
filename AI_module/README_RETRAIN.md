# Retraining Package (Web IDS)

This zip gives you the missing training scripts.

## You MUST have a labeled dataset
To retrain, you need a CSV that contains:
- `classification` column (0=benign, 1=attack)
- all other columns = numeric features

Default expected filename:
- `merged_web_traffic_features_rich_numeric.csv`

## Where to put these files
Put them in:
`C:\Web Sec Project\ai_ids\`

Example:
```
C:\Web Sec Project\ai_ids\
  merged_web_traffic_features_rich_numeric.csv
  trained_model.py
  train_model_fast.py
  requirements.txt
```

## Install dependencies
```
pip install -r requirements.txt
```

## Retrain (full tuning, slower)
```
python trained_model.py
```

## Retrain (FAST, recommended)
```
python train_model_fast.py
```

## Output
Creates/overwrites:
- `rf_web_ids_model.pkl`

If you want a custom output path:
```
python trained_model.py --out "C:\Web Sec Project\ai_ids\rf_web_ids_model.pkl"
```
