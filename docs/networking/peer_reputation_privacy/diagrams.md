# Peer Reputation Privacy System - Diagrams

## 1. System Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                  Peer Reputation Privacy System               │
├──────────────────┬─────────────────────┬────────────────────┤
│  Score Privacy   │ Share Distribution   │ Statistical Privacy │
├──────────────────┼─────────────────────┼────────────────────┤
│ - Encryption     │ - Secret Sharing     │ - Aggregation      │
│ - Noise Injection│ - Threshold Crypto   │ - Anonymization    │
│ - Normalization  │ - Share Recovery     │ - Mean/StdDev      │
└──────────────────┴─────────────────────┴────────────────────┘
```

## 2. Reputation Score Flow

```
   Raw Score                Final Score
      │                         ▲
      ▼                         │
┌──────────────┐    ┌──────────────────┐    ┌─────────────┐
│  Calculate   │ -> │ Add Noise (±5%)   │ -> │  Normalize  │
│Base Metrics  │    │& Weight Components│    │  [0.0-1.0]  │
└──────────────┘    └──────────────────┘    └─────────────┘
```

## 3. Share Distribution Process

```
                  Original Score
                       │
                       ▼
           ┌─────────────────────┐
           │  Encrypt Score      │
           └─────────────────────┘
                       │
                       ▼
           ┌─────────────────────┐
           │  Generate N Shares  │
           └─────────────────────┘
                       │
            ┌─────────┴─────────┐
            ▼         ▼         ▼
     ┌──────────┐┌──────────┐┌──────────┐
     │Share 1   ││Share 2   ││Share N   │
     └──────────┘└──────────┘└──────────┘
            │         │         │
            ▼         ▼         ▼
     ┌──────────┐┌──────────┐┌──────────┐
     │Peer 1    ││Peer 2    ││Peer N    │
     └──────────┘└──────────┘└──────────┘
```

## 4. Score Privacy Mechanism

```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│Success Ratio   │     │Latency Score   │     │Diversity Score │
│   [0.0-1.0]   │     │   [0.0-1.0]    │     │   [0.0-1.0]    │
└───────┬────────┘     └───────┬────────┘     └───────┬────────┘
        │                      │                       │
        ▼                      ▼                       ▼
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│Add Noise ±5%   │     │Add Noise ±5%   │     │Add Noise ±5%   │
└───────┬────────┘     └───────┬────────┘     └───────┬────────┘
        │                      │                       │
        ▼                      ▼                       ▼
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│Weight: 0.4     │     │Weight: 0.3     │     │Weight: 0.3     │
└───────┬────────┘     └───────┬────────┘     └───────┬────────┘
        │                      │                       │
        └──────────────┬──────────────────────┘
                       ▼
             ┌────────────────────┐
             │Combined Final Score│
             │     [0.0-1.0]     │
             └────────────────────┘
```

## 5. Statistical Privacy Flow

```
Individual Scores                 Aggregated Stats
     ┌───┐
     │S1 │──┐
     └───┘  │    ┌─────────────┐    ┌────────────┐
     ┌───┐  ├───►│ Anonymize & │───►│Mean        │
     │S2 │──┤    │ Aggregate   │    │StdDev      │
     └───┘  │    └─────────────┘    │Count       │
     ┌───┐  │                       └────────────┘
     │S3 │──┘
     └───┘
```

## 6. Encryption Process

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│Generate Key  │───►│Generate Nonce│───►│Create Cipher │
└──────────────┘    └──────────────┘    └──────────────┘
       │                   │                    │
       └───────────┬──────┘                    │
                   ▼                           ▼
            ┌──────────────┐           ┌──────────────┐
            │Score Data    │──────────►│Encrypt Score │
            └──────────────┘           └──────────────┘
                                             │
                                             ▼
                                    ┌──────────────┐
                                    │Encrypted Data│
                                    └──────────────┘
```

## 7. Thread Safety Model

```
┌─────────────────────────────────────────────────────┐
│                  Connection Pool                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │Active Conns │  │Peer Scores  │  │Banned Peers │ │
│  │Arc<RwLock>  │  │Arc<RwLock>  │  │Arc<RwLock>  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│         │               │                │          │
│         ▼               ▼                ▼          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │Read Access  │  │Read Access  │  │Read Access  │ │
│  │Multiple     │  │Multiple     │  │Multiple     │ │
│  │Readers      │  │Readers      │  │Readers      │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│         │               │                │          │
│         ▼               ▼                ▼          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │Write Access │  │Write Access │  │Write Access │ │
│  │Single       │  │Single       │  │Single       │ │
│  │Writer       │  │Writer       │  │Writer       │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│                                                     │
└─────────────────────────────────────────────────────┘
``` 