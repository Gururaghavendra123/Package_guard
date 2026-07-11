"""GraphSAGE node-classifier (Sem 8).

A 2-layer GraphSAGE over dependency subgraphs. Each node's feature vector is the 5 per-package
features; the model predicts per-node maliciousness from features + neighbourhood structure.
This is what catches the "poisoned chain" case: a clean-looking package whose *neighbour* is
malicious — the graph model propagates that risk, whereas the per-package XGBoost cannot see it.

Torch/PyG are optional deps (`pip install -e ".[gnn]"`). Everything here degrades gracefully:
if the model file or the libraries are missing, `available()` is False and the engine simply
omits the graph score.
"""

from __future__ import annotations

from pathlib import Path

from packageguard.core.features import FEATURE_ORDER

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "graphsage_model.pt"
_N_FEATURES = len(FEATURE_ORDER)


def _torch_available() -> bool:
    try:
        import torch  # noqa: F401
        import torch_geometric  # noqa: F401
        return True
    except ImportError:
        return False


def build_model(hidden: int = 32):
    """Construct the GraphSAGE module (import-guarded so the package imports without torch)."""
    import torch.nn as nn
    from torch_geometric.nn import SAGEConv

    class GraphSAGE(nn.Module):
        def __init__(self, in_dim: int, hidden_dim: int):
            super().__init__()
            self.conv1 = SAGEConv(in_dim, hidden_dim)
            self.conv2 = SAGEConv(hidden_dim, hidden_dim)
            self.head = nn.Linear(hidden_dim, 1)
            self.act = nn.ReLU()

        def forward(self, x, edge_index):
            h = self.act(self.conv1(x, edge_index))
            h = self.act(self.conv2(h, edge_index))
            return self.head(h).squeeze(-1)  # per-node logit

    return GraphSAGE(_N_FEATURES, hidden)


class GnnScorer:
    """Loads the trained GraphSAGE and scores the nodes of a subgraph."""

    def __init__(self) -> None:
        self._model = None

    def available(self) -> bool:
        return _torch_available() and MODEL_PATH.exists()

    def _load(self):
        if self._model is None:
            import torch
            self._model = build_model()
            self._model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
            self._model.eval()
        return self._model

    def score_nodes(self, x: list[list[float]], edge_index: list[list[int]]) -> list[float]:
        """Return a malicious-probability per node (same order as x)."""
        import torch
        model = self._load()
        xt = torch.tensor(x, dtype=torch.float)
        ei = torch.tensor(edge_index, dtype=torch.long) if edge_index[0] else \
            torch.empty((2, 0), dtype=torch.long)
        with torch.no_grad():
            logits = model(xt, ei)
            probs = torch.sigmoid(logits)
        return [float(p) for p in probs]
