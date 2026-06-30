import torch
import torch.nn as nn

class NetworkAutoencoder(nn.Module):
    def __init__(self, input_dim=16, latent_dim=4):
        """
        Deep Autoencoder Architecture for Network Anomaly Detection.
        
        Parameters:
        - input_dim: Number of extracted statistical packet features (default: 16)
        - latent_dim: The compressed bottleneck representation tier (default: 4)
        """
        super(NetworkAutoencoder, self).__init__()
        
        # 1. ENCODER: Compresses the high-dimensional packet vectors
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 12),
            nn.BatchNorm1d(12),
            nn.ReLU(),
            nn.Dropout(0.1),
            
            nn.Linear(12, 8),
            nn.BatchNorm1d(8),
            nn.ReLU(),
            
            nn.Linear(8, latent_dim),
            nn.ReLU()  # Compressed latent feature representation
        )
        
        # 2. DECODER: Reconstructs the original packet vectors from bottleneck
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 8),
            nn.BatchNorm1d(8),
            nn.ReLU(),
            nn.Dropout(0.1),
            
            nn.Linear(8, 12),
            nn.BatchNorm1d(12),
            nn.ReLU(),
            
            nn.Linear(12, input_dim),
            nn.Sigmoid()  # Assumes features are min-max scaled between 0 and 1
        )

    def forward(self, x):
        """Executes full pass compression-decompression cycle."""
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

    def get_reconstruction_loss(self, x):
        """
        Calculates per-packet Mean Squared Error (MSE).
        High loss values directly flag zero-day intrusion signatures.
        """
        self.eval()  # Set to evaluation mode
        with torch.no_grad():
            reconstructed = self.forward(x)
            # Compute element-wise MSE loss without reducing across the batch
            loss = torch.mean((x - reconstructed) ** 2, dim=1)
        return loss

if __name__ == "__main__":
    # Diagnostic structural verification check
    print("[*] Instantiating PyTorch Network Architecture...")
    model = NetworkAutoencoder(input_dim=16, latent_dim=4)
    print(model)
    
    # Simulate a batch of 3 mock network packets
    mock_batch = torch.rand(3, 16)
    output = model(mock_batch)
    print(f"\n[*] Structural Pass Verification Success!")
    print(f"    Input Shape  -> {mock_batch.shape}")
    print(f"    Output Shape -> {output.shape}")
