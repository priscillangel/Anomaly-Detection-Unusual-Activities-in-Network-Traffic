# Load Dataset
datasetA <- read.csv("DatasetD.csv", header = FALSE) #UNSW
datasetB <- read.csv("DatasetB.csv", header = TRUE, sep = "|") #Malware Detection

# Check the number of columns
ncol(datasetA)


# Assign column names
colnames(datasetA) <- c("srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", 
                        "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", 
                        "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len", 
                        "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", 
                        "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", 
                        "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
                        "ct_dst_sport_ltm", "ct_dst_src_ltm","attack_cat", "Label")
install.packages("uuid")
library(uuid)
datasetA$ID <- replicate(nrow(datasetA), UUIDgenerate())


#Rename dataset headernya biar sama

names(datasetB)[names(datasetB) == "uid"] <- "ID"

names(datasetA)[names(datasetA) == "Stime"] <- "TimeStamp"
names(datasetB)[names(datasetB) == "ts"] <- "TimeStamp"

names(datasetA)[names(datasetA) == "srcip"] <- "SourceIP"
names(datasetB)[names(datasetB) == "id.orig_h"] <- "SourceIP"

names(datasetA)[names(datasetA) == "sport"] <- "SourcePort"
names(datasetB)[names(datasetB) == "id.orig_p"] <- "SourcePort"

names(datasetA)[names(datasetA) == "dstip"] <- "DestinationIP"
names(datasetB)[names(datasetB) == "id.resp_h"] <- "DestinationIP"

names(datasetA)[names(datasetA) == "dsport"] <- "DestinationPort"
names(datasetB)[names(datasetB) == "id.resp_p"] <- "DestinationPort"

names(datasetA)[names(datasetA) == "proto"] <- "Protocol"
names(datasetB)[names(datasetB) == "proto"] <- "Protocol"

names(datasetA)[names(datasetA) == "service"] <- "Service"
names(datasetB)[names(datasetB) == "service"] <- "Service"

names(datasetA)[names(datasetA) == "dur"] <- "Duration"
names(datasetB)[names(datasetB) == "duration"] <- "Duration"

names(datasetA)[names(datasetA) == "sbytes"] <- "BytesSent"
names(datasetB)[names(datasetB) == "orig_bytes"] <- "BytesSent"

names(datasetA)[names(datasetA) == "dbytes"] <- "BytesReceived"
names(datasetB)[names(datasetB) == "resp_bytes"] <- "BytesReceived"

names(datasetA)[names(datasetA) == "state"] <- "State"
names(datasetB)[names(datasetB) == "conn_state"] <- "State"

names(datasetA)[names(datasetA) == "Spkts"] <- "PacketsSent"
names(datasetB)[names(datasetB) == "orig_pkts"] <- "PacketsSent"

names(datasetA)[names(datasetA) == "Dpkts"] <- "PacketsReceived"
names(datasetB)[names(datasetB) == "resp_pkts"] <- "PacketsReceived"

names(datasetB)[names(datasetB) == "label"] <- "Label"

#Cek header apakah sudah berubah
head(datasetA)
head(datasetB)

common_columns <- intersect(names(datasetA), names(datasetB)) #15 common columns

datasetA$Label[datasetA$Label == 0] <- "Benign"
datasetA$Label[datasetA$Label == 1] <- "Malicious"

# Convert UNIX timestamp to datetime
datasetA$Time <- as.POSIXct(datasetA$Time, origin = "1970-01-01", tz = "UTC")
datasetB$Time <- as.POSIXct(datasetB$Time, origin = "1970-01-01", tz = "UTC")

#Subset datasets to only include common columns
datasetA_common <- datasetA[common_columns]
datasetB_common <- datasetB[common_columns]

#Merge the datasets (row-wise, assuming same structure for common columns)
merged_dataset <- rbind(datasetA_common, datasetB_common)

merged_dataset$Label[merged_dataset$Label == "Benign"] <- 0
merged_dataset$Label[merged_dataset$Label == "Malicious"] <- 1

#Hapus data duplikat
merged_dataset <- merged_dataset[!duplicated(merged_dataset), ]

# Check Missing Value untuk Dataset A
colSums(is.na(merged_dataset)) #0 semua

#Replace "-" jadi NA
merged_dataset[] <- lapply(merged_dataset, function(x) replace(x, x == '-', NA))

colSums(is.na(merged_dataset))
# SourcePort :2 -> < 10% replace with mode
# DestinationPort: 7 -> < 10% replace with mode
# Duration : 796300 -> >10% hapus
# BytesSent : 796300 -> >10% hapus
# BytesReceived : 796300 -> >10% hapus
# Service : 1436163 -> >10% hapus

# Function to calculate mode
calculate_mode <- function(x) {
  ux <- na.omit(x) # Remove NA values
  ux <- ux[ux != ""] # Remove empty string values
  ux <- as.numeric(ux) # Convert to numeric if ports are numeric
  ux[which.max(tabulate(match(x, ux)))] # Find the mode
}

# Replace empty values with the mode for SourcePort
sourceport_mode <- calculate_mode(merged_dataset$SourcePort)
merged_dataset$SourcePort[is.na(merged_dataset$SourcePort)] <- sourceport_mode

# Replace empty values with the mode for DestinationPort
destinationport_mode <- calculate_mode(merged_dataset$DestinationPort)
merged_dataset$DestinationPort[is.na(merged_dataset$DestinationPort)] <- destinationport_mode

#Handle missing value 
merged_dataset$SourcePort[is.na(merged_dataset$SourcePort)] <- sourceport_mode
merged_dataset$DestinationPort[is.na(merged_dataset$DestinationPort)] <- destinationport_mode

#Cek data NA lagi di dataset A
colSums(is.na(merged_dataset))

#Hapus Duration, BytesSent, BytesReceived, Service  karena missing value > 10%
merged_dataset<- merged_dataset[, colSums(is.na(merged_dataset)) == 0] 

#Cek data NA lagi di dataset A
colSums(is.na(merged_dataset))

# Convert all categorical columns to factors and encode as integers
library(dplyr)

encoded_dataset <- merged_dataset %>%
  mutate(across(where(is.character), as.factor)) %>%
  mutate(across(where(is.factor), as.integer))


## XGBOOST Model ##

# Load necessary libraries
library(xgboost)
library(caret)   

#Split the data into train and test sets
set.seed(42)
split <- createDataPartition(encoded_dataset$Label, p = 0.8, list = FALSE)
train_data <- encoded_dataset[split, ]
test_data <- encoded_dataset[-split, ]

# Extract features (X) and labels (y)
train_X <- as.matrix(train_data %>% select(-Label, -ID))
train_y <- train_data$Label
test_X <- as.matrix(test_data %>% select(-Label, -ID))
test_y <- test_data$Label

# Ensure train_X is a data.frame
train_X <- as.data.frame(train_X)

# Convert all categorical columns to factors and then to integers
train_X <- train_X %>%
  mutate(across(where(is.character), as.factor)) %>%
  mutate(across(where(is.factor), as.integer))

# Ensure train_X is a numeric matrix
train_X <- as.matrix(train_X)

# Ensure the label is numeric
train_y <- as.numeric(train_y)

train_y <- ifelse(train_y == 2, 1, 0)

test_y <- ifelse(test_y == 2, 1, 0)

#Train the XGBoost model
xgb_model <- xgboost(
  data = train_X,
  label = train_y,
  objective = "binary:logistic",
  nrounds = 100,
  eval_metric = "logloss",
  lambda = 1,   # L2 regularization
  alpha = 1,    # L1 regularization
  early_stopping_rounds = 10,  # Stop training if no improvement for 10 rounds
  max_depth= 5,
  verbose = 0
)

#Make predictions
pred_probs <- predict(xgb_model, test_X)
pred_labels <- ifelse(pred_probs > 0.5, 1, 0)


#Evaluate the model
conf_matrix <- confusionMatrix(factor(pred_labels), factor(test_y))
print(conf_matrix)

# Load necessary library
library(ggplot2)

# Prepare data for plotting
# Create a data frame that includes test data, predictions, and labels
plot_data <- data.frame(
  SourceIP = as.factor(test_data$SourceIP),
  TrueLabel = factor(test_y, levels = c(0, 1), labels = c("Benign", "Malicious")),
  PredictedLabel = factor(pred_labels, levels = c(0, 1), labels = c("Benign", "Malicious")),
  AnomalyScore = pred_probs, # Use probabilities as anomaly scores
  Index = 1:nrow(test_data) # Row index for the X-axis
)

# Select only the top 100000 SourceIP based on anomaly score
top_ips <- plot_data_varied %>%
  arrange(desc(AnomalyScore)) %>%
  head(100000)  # You can adjust this number

# Plot the top 100 000 SourceIP with varied anomaly scores
ggplot(top_ips, aes(x = AnomalyScore, y = SourceIP, color = PredictedLabel)) +
  geom_point(aes(size = AnomalyScore), alpha = 0.6) +
  labs(
    title = "Anomaly Detection Scatter Plot (Top 100,000 Source IPs)",
    x = "Anomaly Score",
    y = "Source IP",
    color = "Predicted Label",
    size = "Anomaly Score"
  ) +
  scale_color_manual(values = c("Benign" = "blue", "Malicious" = "red")) +
  theme_minimal() +
  theme(
    axis.text.x = element_text(angle = 45, hjust = 1),
    axis.text.y = element_text(size = 8),
    legend.position = "top"
  )

