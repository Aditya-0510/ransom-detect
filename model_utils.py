# model_utils.py

import pandas as pd
import numpy as np

# Converts hex strings like "0xABC" to integers
def hex_to_int_frame(Xdf: pd.DataFrame):
    Xc = Xdf.copy()
    for c in Xc.columns:
        Xc[c] = (
            Xc[c].astype(str)
                 .str.extract(r'(0x[0-9A-Fa-f]+)', expand=False)
                 .apply(lambda s: int(s, 16) if isinstance(s, str) and s.startswith("0x") else np.nan)
        )
    return Xc

# Converts list-like strings → count
def listlen_frame(Xdf: pd.DataFrame):
    Xc = Xdf.copy()
    for c in Xc.columns:
        s = Xc[c].astype(str)
        is_list = s.str.startswith("[")
        Xc.loc[is_list, c] = s[is_list].apply(lambda v: v.count(",") + 1 if v.strip("[]").strip() else 0)
        Xc.loc[~is_list, c] = np.nan
    return Xc
