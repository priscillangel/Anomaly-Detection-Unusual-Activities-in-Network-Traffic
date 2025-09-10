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

#Add column ID in Dataset A
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

#Merge the datasets 
merged_dataset <- rbind(datasetA_common, datasetB_common)

merged_dataset$Label[merged_dataset$Label == "Benign"] <- 0
merged_dataset$Label[merged_dataset$Label == "Malicious"] <- 1

#Hapus data duplikat
merged_dataset <- merged_dataset[!duplicated(merged_dataset), ]

# Check Missing Value untuk Dataset A
colSums(is.na(merged_dataset)) #1 708 749

#Replace "-" jadi NA
merged_dataset[] <- lapply(merged_dataset, function(x) replace(x, x == '-', NA))

# Check Missing Value lagi untuk Dataset A
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

#Cek data NA lagi di dataset A
colSums(is.na(merged_dataset))

#Hapus Duration, BytesSent, BytesReceived, Service  karena missing value > 10%
merged_dataset<- merged_dataset[, colSums(is.na(merged_dataset)) == 0] 

#Cek data NA lagi di dataset A
colSums(is.na(merged_dataset)) #sisa 11 kolom


                  ##BUAT CORRELATION MATRIX
#Install Relevant Packages
install.packages("DataExplorer")

library(ggplot2)
library(dplyr)
library(tidyr)
library(DataExplorer)
library(corrplot)
library(scales)

# Convert all categorical columns to factors and encode as integers
encoded_dataset <- merged_dataset %>%
  mutate(across(where(is.character), as.factor)) %>%
  mutate(across(where(is.factor), as.integer))

#Ubah Atribut jadi numeric type
encoded_dataset$SourceIP <- as.numeric(encoded_dataset$SourceIP)
encoded_dataset$SourcePort <- as.numeric(encoded_dataset$SourcePort)
encoded_dataset$DestinationIP <- as.numeric(encoded_dataset$DestinationIP)
encoded_dataset$DestinationPort<- as.numeric(encoded_dataset$DestinationPort)
encoded_dataset$Protocol <- as.numeric(encoded_dataset$Protocol)

encoded_dataset$Label <- as.numeric(encoded_dataset$Label)
encoded_dataset$ID <- as.numeric(encoded_dataset$ID)

#1. Correlation Heatmap
numeric_columns <- encoded_dataset %>% select(where(is.numeric))
correlation_matrix <- cor(numeric_columns, use = "pairwise.complete.obs")

corrplot(
  correlation_matrix,
  method = "color",             # Use color-coded cells
  type = "upper",               # Show only upper triangle
  tl.cex = 0.8,                 # Adjust text size for labels
  tl.col = "black",             # Set text color for labels
  number.cex = 0.7,            # Adjust the size of correlation numbers
  addCoef.col = "black",        # Set text color for the numbers
  number.format = ".2f",
  title = "Correlation Matrix",
  mar = c(0, 0, 2, 0)
)

    ##PLOTTING HISTOGRAMS AND OTHER SPECIFIC CHARTS
merged_dataset$TimeStamp <- as.POSIXct(merged_dataset$Time, origin = "1970-01-01", tz = "UTC")

# Extract hour in "HH" format
# Assuming Timestamp is in POSIX format, convert to hour of the day or day of the week
merged_dataset$hour <- as.POSIXlt(merged_dataset$TimeStamp)$hour

# Count the number of Malicious (1) and Benign (0) by hour
hourly_activity <- merged_dataset %>%
  group_by(hour, Label) %>%
  summarise(count = n()) %>%
  ungroup()

# Plotting the line plot to show activities over the hours of the day
ggplot(hourly_activity, aes(x = hour, y = count, color = factor(Label), group = factor(Label))) +
  geom_line(size = 1.2) +
  scale_color_manual(values = c("0" = "green", "1" = "red"), labels = c("Benign", "Malicious")) +
  labs(title = "Activity by Hour of the Day", x = "Hour of Day", y = "Count", color = "Activity Type") +
  theme_minimal() +
  theme(legend.position = "top")

#Link between State to Label
ggplot(merged_dataset, aes(x = State, fill = factor(Label))) +
  geom_bar(position = "fill", alpha = 0.7) +
  scale_fill_manual(values = c("0" = "green", "1" = "red"), labels = c("Benign", "Malicious")) +
  labs(title = "Distribution of States by Activity Label", x = "State of Connection", y = "Proportion") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

#Link between PacketsSent and Labels
# Set the threshold for insignificant counts
threshold_packet <- 2000  # Adjust this value based on your dataset

# Group values below the threshold into "Others"
merged_dataset <- merged_dataset %>%
  mutate(PacketsSent_Grouped = ifelse(table(PacketsSent)[as.character(PacketsSent)] < threshold_packet, "Others", as.character(PacketsSent)))

ggplot(merged_dataset, aes(x = factor(PacketsSent_Grouped), fill = factor(Label))) +
  geom_bar(stat = "count", position = "fill", alpha = 0.7) +
  scale_fill_manual(values = c("0" = "green", "1" = "red"), 
                    name = "Label", 
                    labels = c("Benign", "Malicious")) +
  labs(title = "Count of Packets Sent by Activity Type", 
       x = "Packet Sent", 
       y = "Proportion of Count") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))


#Link between DestinationIP and Labels
# Aggregating to find the top destination IPs for Malicious activity
top_dest_ips <- merged_dataset %>%
  filter(Label == 1) %>%
  group_by(DestinationIP) %>%
  summarise(malicious_count = n()) %>%
  top_n(10, malicious_count)

# Plotting top DestinationIP with Malicious activity count
ggplot(top_dest_ips, aes(x = reorder(DestinationIP, malicious_count), y = malicious_count, fill = "red")) +
  geom_bar(stat = "identity") +
  labs(title = "Top Destination IPs for Malicious Activity", x = "Destination IP", y = "Malicious Activity Count") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

#Link between SourceIP and Labels
# Aggregating to find the top SourceIP involved in Malicious activity
top_source_ips <- merged_dataset %>%
  filter(Label == 1) %>%
  group_by(SourceIP) %>%
  summarise(malicious_count = n()) %>%
  top_n(10, malicious_count)

# Plotting top SourceIP with Malicious activity count
ggplot(top_source_ips, aes(x = reorder(SourceIP, malicious_count), y = malicious_count, fill = "red")) +
  geom_bar(stat = "identity") +
  labs(title = "Top Source IPs for Malicious Activity", x = "Source IP", y = "Malicious Activity Count") +
  scale_y_continuous(labels = label_number(scale = 1e-6, suffix = "M")) +  # Format large counts as millions
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

#Link between SourcePort and Labels
threshold_sourceport <- 100

# Group SourcePorts with counts below the threshold into "Others"
merged_dataset <- merged_dataset %>%
  mutate(SourcePort_Grouped = ifelse(table(SourcePort)[as.character(SourcePort)] < threshold_sourceport, "Others", as.character(SourcePort)))

# Plotting the SourcePort counts with the "Others" group and showing proportions
ggplot(merged_dataset, aes(x = factor(SourcePort_Grouped), fill = factor(Label))) + 
  geom_bar(position = "fill", alpha = 0.7) +
  scale_fill_manual(values = c("0" = "green", "1" = "red"), labels = c("Benign", "Malicious")) +
  labs(title = "Proportion of Malicious vs Benign by Source Port", 
       x = "Source Port", 
       y = "Proportion") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

