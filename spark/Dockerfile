FROM apache/spark:3.5.1-python3
USER root
WORKDIR /app
COPY detections.py stream_job.py ./
ENV SPARK_PACKAGES="org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1,io.delta:delta-spark_2.12:3.2.0"
CMD /opt/spark/bin/spark-submit \
      --master "local[*]" \
      --packages "$SPARK_PACKAGES" \
      --conf spark.jars.ivy=/tmp/.ivy2 \
      --py-files /app/detections.py \
      /app/stream_job.py
