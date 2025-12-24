# %%
import pandas as pd
df = pd.read_feather('/allah/data/ml/TemaSlope-ETH_USDT_USDT-1224-1509.feather')
df

# %%
df.describe()

# %%
df.info()

# %%
df.head()

# %%
df.tail()

# %% rows that with profit_ratio not null
df[df['profit_ratio'].notna()].head()
# %%
