# Load Dataset
datasetA <- read.csv("Malware_Dataset.csv", header = TRUE, sep = "|")
datasetB <- read.csv("UNSW_Dataset.csv", header = FALSE)

# Assign Column Names (datasetB)
ncol(datasetB)
colnames(datasetB) <- c("srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
                        "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
                        "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
                        "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
                        "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
                        "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
                        "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label")

# Remove Duplicate Rows
datasetA <- datasetA[!duplicated(datasetA), ]
datasetB <- datasetB[!duplicated(datasetB), ]

# Add new column @datasetB + Generate ID
# install.packages("uuid")
library(uuid)
datasetB$ID <- replicate(nrow(datasetB), UUIDgenerate())

# Identify Common Attributes
intersect(names(datasetA), names(datasetB))
# proto service

# Align Column Names (manually checked)
names(datasetA)[names(datasetA) == "uid"] <- "ID"
names(datasetA)[names(datasetA) == "ts"] <- "Timestamp"
names(datasetA)[names(datasetA) == "id.orig_h"] <- "SourceIP"
names(datasetA)[names(datasetA) == "id.orig_p"] <- "SourcePort"
names(datasetA)[names(datasetA) == "id.resp_h"] <- "DestinationIP"
names(datasetA)[names(datasetA) == "id.resp_p"] <- "DestinationPort"
names(datasetA)[names(datasetA) == "proto"] <- "Protocol"
names(datasetA)[names(datasetA) == "service"] <- "Service"
names(datasetA)[names(datasetA) == "duration"] <- "Duration"
names(datasetA)[names(datasetA) == "orig_bytes"] <- "BytesSent"
names(datasetA)[names(datasetA) == "resp_bytes"] <- "BytesReceived"
names(datasetA)[names(datasetA) == "conn_state"] <- "State"
names(datasetA)[names(datasetA) == "orig_pkts"] <- "PacketsSent"
names(datasetA)[names(datasetA) == "resp_pkts"] <- "PacketsReceived"
names(datasetA)[names(datasetA) == "label"] <- "Label"

names(datasetB)[names(datasetB) == "Stime"] <- "Timestamp"
names(datasetB)[names(datasetB) == "srcip"] <- "SourceIP"
names(datasetB)[names(datasetB) == "sport"] <- "SourcePort"
names(datasetB)[names(datasetB) == "dstip"] <- "DestinationIP"
names(datasetB)[names(datasetB) == "dsport"] <- "DestinationPort"
names(datasetB)[names(datasetB) == "proto"] <- "Protocol"
names(datasetB)[names(datasetB) == "service"] <- "Service"
names(datasetB)[names(datasetB) == "dur"] <- "Duration"
names(datasetB)[names(datasetB) == "sbytes"] <- "BytesSent"
names(datasetB)[names(datasetB) == "dbytes"] <- "BytesReceived"
names(datasetB)[names(datasetB) == "state"] <- "State"
names(datasetB)[names(datasetB) == "Spkts"] <- "PacketsSent"
names(datasetB)[names(datasetB) == "Dpkts"] <- "PacketsReceived"

intersect(names(datasetA), names(datasetB))
# 15 common columns

# Replace 0-1 to Benign-Malicious
datasetA$Label[datasetA$Label == 0] <- "Benign"
datasetA$Label[datasetA$Label == 1] <- "Malicious"

datasetB$Label[datasetB$Label == 0] <- "Benign"
datasetB$Label[datasetB$Label == 1] <- "Malicious"

# Subset Data Frame for Aligned Columns
subsetA <- datasetA[, c("ID", "Timestamp", "SourceIP", "SourcePort", "DestinationIP",
                        "DestinationPort", "Protocol", "Service", "Duration", "BytesSent",
                        "BytesReceived", "State", "PacketsSent", "PacketsReceived", "Label")]

subsetB <- datasetB[, c("ID", "Timestamp", "SourceIP", "SourcePort", "DestinationIP",
                        "DestinationPort", "Protocol", "Service", "Duration", "BytesSent",
                        "BytesReceived", "State", "PacketsSent", "PacketsReceived", "Label")]

# NA di kedua dataset ditandai dengan '-', replace dg NA
subsetA[] <-lapply(subsetA, function(x) replace(x, x == '-', NA))
subsetB[] <-lapply(subsetB, function(x) replace(x, x == '-', NA))

# Convert UNIX Timestamp to Datetime
subsetA$Timestamp <- as.POSIXct(subsetA$Timestamp, origin = "1970-01-01", tz = "UTC")
subsetB$Timestamp <- as.POSIXct(subsetB$Timestamp, origin = "1970-01-01", tz = "UTC")

# Check Attributes Data Type & Typecast
class(subsetA$PacketsReceived)
class(subsetB$PacketsReceived)

subsetB$SourcePort <- as.numeric(subsetB$SourcePort)
subsetB$DestinationPort <- as.numeric(subsetB$SourcePort)
subsetA$Duration <- as.numeric(subsetA$Duration)
subsetA$BytesSent <- as.integer(subsetA$BytesSent)
subsetA$BytesReceived <- as.integer(subsetA$BytesReceived)
subsetB$PacketsSent <- as.numeric(subsetB$PacketsSent)
subsetB$PacketsReceived <- as.numeric(subsetB$PacketsReceived)

# Calculate the ratio of Benign-Malicious
anomalyA <- round(3000 * sum(subsetA$Label == "Malicious") / nrow(subsetA))
normalA <- 3000 - anomalyA

anomalyB <- round(3000 * sum(subsetB$Label == "Malicious") / nrow(subsetB))
normalB <- 3000 - anomalyB

# Randomly select data from each class
sample_anomalyA <- subsetA[subsetA$Label == "Malicious",][sample(sum(subsetA$Label == "Malicious"), anomalyA), ]
sample_normalA <- subsetA[subsetA$Label == "Benign",][sample(sum(subsetA$Label == "Benign"), normalA), ]

sample_anomalyB <- subsetB[subsetB$Label == "Malicious",][sample(sum(subsetB$Label == "Malicious"), anomalyB), ]
sample_normalB <- subsetB[subsetB$Label == "Benign",][sample(sum(subsetB$Label == "Benign"), normalB), ]

# Combine sampled data
sampleA <- rbind(sample_anomalyA, sample_normalA)
sampleB <- rbind(sample_anomalyB, sample_normalB)

# Merge data & shuffle
merged_dataset <- merge(sampleA, sampleB, all = TRUE)
merged_dataset <- merged_dataset[sample(nrow(merged_dataset)), ]

# Standarize Protocol & Service (uppercase)
merged_dataset$Protocol <- toupper(merged_dataset$Protocol)
merged_dataset$Service <- toupper(merged_dataset$Service)

# Check Missing Value
colSums(is.na(merged_dataset))
# Service       : 4815 
# Duration      : 2352
# BytesSent     : 2352
# BytesReceived : 2352

# To determine whether those attributes should be removed or not,
# we need to plot correlation matrix

encoded_data <- merged_dataset

# Replace the NA value
encoded_data$Service[is.na(encoded_data$Service)] <- 'NA'
encoded_data$Duration[is.na(encoded_data$Duration)] <- 0
encoded_data$BytesSent[is.na(encoded_data$BytesSent)] <- 0
encoded_data$BytesReceived[is.na(encoded_data$BytesReceived)] <- 0

# Check Attributes Type
attr_type <- sapply(encoded_data, class)
print(attr_type)

# Encode Attributes
encoded_data$ID <- as.numeric(factor(encoded_data$ID))
encoded_data$Timestamp <- as.numeric(factor(encoded_data$Timestamp))
encoded_data$SourceIP <- as.numeric(factor(encoded_data$SourceIP))
encoded_data$DestinationIP <- as.numeric(factor(encoded_data$DestinationIP))
encoded_data$Protocol <- as.numeric(factor(encoded_data$Protocol))
encoded_data$Service <- as.numeric(factor(encoded_data$Service))
encoded_data$State <- as.numeric(factor(encoded_data$State))
encoded_data$Label <- as.numeric(factor(encoded_data$Label))

# Plot Correlation Matrix
# install.packages("corrplot")
# install.packages("gplots")
library(corrplot)
library(gplots)

corr_mat <- cor(encoded_data, use = "complete.obs")
corrplot(corr_mat, method = "circle")
textplot(round(corr_mat, 2), cex = 0.5)
title("Correlation Coefficients Table")

# Correlation Coefficient Tables
# Label-Service       : 0.19
# Label-Duration      : 0.11
# Label-BytesSent     : -0.18
# Label-BytesReceived : -0.11
# cenderung rendah sehingga kita remove, karena NA diatas 10%

encoded_data <- subset(encoded_data, select = -c(Service, Duration, BytesSent, BytesReceived))
selectedData <- subset(encoded_data, select = c(Timestamp, PacketsSent, State, DestinationIP, SourcePort, SourceIP, Label))

## ISOLATION FOREST IMPLEMENTATION ##
# install.packages("isotree")
library(isotree)

# Split data into 80% training and 20% testing
set.seed(42)
train_indices <- sample(seq_len(nrow(selectedData)), size = 0.8 * nrow(selectedData))
train_data <- selectedData[train_indices, ]
test_data <- selectedData[-train_indices, ]

table(train_data$Label)
table(test_data$Label)

# Model Training
iso_forest <- isolation.forest(train_data, ntrees = 100, sample_size = 480)

# Predict anomaly scores on test data
anomaly_score <- predict(iso_forest, test_data, type = "score")

# Define threshold to identify anomaly
threshold <- quantile (anomaly_score, 0.95) # 95th percentile
anomalies <- ifelse(anomaly_score > threshold, "Malicious", "Benign")
# 2 = anomaly, 1 = normal

test_data$Label[test_data$Label == 1] <- "Benign"
test_data$Label[test_data$Label == 2] <- "Malicious"

# Add scores and anomaly labes to test data
test_data$AnomalyScore <- anomaly_score
test_data$PredictedLabel <- anomalies

# Accuracy: 1-Anomaly, 0-Normal
predicted_label <- ifelse(anomalies == "Malicious", 1, 0)
true_label <- ifelse(test_data$Label == "Malicious", 1, 0)

accuracy <- (sum(predicted_label == true_label / length(true_label)))/nrow(test_data) * 100
print(paste("Accuracy of the model: ", accuracy))

# Confusion Matrix
# install.packages("caret")
library(caret)

conf_matrix <- confusionMatrix(factor(predicted_label), factor(true_label))
print(conf_matrix)

# Visualization
library(ggplot2)

# Create a scatter plot: AnomalyScore vs PredictedLabel
ggplot(test_data, aes(x = AnomalyScore, y = SourceIP, color = PredictedLabel)) + 
  geom_point(alpha = 0.7, size = 3) + 
  scale_color_manual(values = c("Benign" = "blue", "Malicious" = "red")) +
  labs(title = "Anomaly Detection using Isolation Forest", 
       x = "Anomaly Score", y = "SourceIP") + 
  theme_minimal() +
  theme(legend.title = element_blank())