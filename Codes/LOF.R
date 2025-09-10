## LOCAL OUTLIER FACTOR ##
# install.packages("dbscan")
library(dbscan)
library(ggplot2)

# Split data into 80% training and 20% testing
set.seed(42)
train_indices <- sample(seq_len(nrow(selectedData)), size = 0.8 * nrow(selectedData))
train_data <- selectedData[train_indices, ]
test_data <- selectedData[-train_indices, ]

# Model Training
k_neighbors <- 20 # number of neighbors for LOF
lof_scores_train <- lof(train_data[, -ncol(train_data)], minPts = k_neighbors)

# Predict anomalies using LOF
threshold <- quantile(lof_scores_train, 0.95)
train_data$AnomalyScore <- lof_scores_train
train_data$PredictedLabel <- ifelse(lof_scores_train > threshold, "Malicious", "Benign")

# Apply LOF to test data
lof_scores_test <- lof(test_data[, -ncol(test_data)], minPts = k_neighbors)
test_data$AnomalyScore <- lof_scores_test
test_data$PredictedLabel <- ifelse(lof_scores_test > threshold, "Malicious", "Benign")

# Calculate Accuracy [manual]: 1 - Malicious, 0 - Benign
test_data$Label[test_data$Label == 1] <- "Benign"
test_data$Label[test_data$Label == 2] <- "Malicious"

predicted_label <- ifelse(test_data$PredictedLabel == "Malicious", 1, 0)
true_label <- ifelse(test_data$Label == "Malicious", 1, 0)
accuracy <- (sum(predicted_label == true_label) / length(true_label)) * 100
print(paste("Accuracy of LOF: ", round(accuracy, 2)))

# Confusion Matrix
library(caret)

conf_matrix <- confusionMatrix(factor(predicted_label), factor(true_label))
print(conf_matrix)

# Visualization 
ggplot(test_data, aes(x = AnomalyScore, y = SourceIP, color = PredictedLabel)) + 
  geom_point(alpha = 0.7, size = 3) + 
  scale_color_manual(values = c("Benign" = "blue", "Malicious" = "red")) +
  labs(title = "Anomaly Detection using Local Outlier Factor (LOF)", 
       x = "Anomaly Score", y = "SourceIP") + 
  theme_minimal() +
  theme(legend.title = element_blank())