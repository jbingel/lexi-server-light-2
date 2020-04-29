FROM python:3.7

# Create api directory
WORKDIR /usr/src/app

# Install requirements
ADD ./requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN python -c "import nltk; nltk.download(\"punkt\")"
RUN python -c "import stanfordnlp; stanfordnlp.download('da', force=True)"
RUN pip install gunicorn

# Get Danish BERT model
#ADD "https://www.dropbox.com/s/dom32pssaifqx5i/da-bert.tar.gz" .
#ADD "https://www.dropbox.com/s/xq3pvshleiswo50/da-bert.zip" .
#ADD "https://jbingel.github.io/files/lexi-resources/da-bert.tgz" .
#ADD "https://www.dropbox.com/s/gyjkc6053bkjeli/da-bert.tar" .
#RUN tar xzf da-bert.tar.gz
#RUN unzip da-bert.zip
#CMD ["tar", "xzf", "da-bert.tar.gz"]
#RUN tar xf da-bert.tar

#RUN curl "https://www.dropbox.com/s/gyjkc6053bkjeli/da-bert.tar" -o da-bert.tar
# RUN wget "https://www.dropbox.com/s/gyjkc6053bkjeli/da-bert.tar"
# RUN tar xf da-bert.tar

# Copy default simplification models
# ADD "https://jbingel.github.io/files/lexi-models/models.tgz" .
# RUN tar xzf models.tgz

# Copy over the project
COPY . /usr/src/app/

# Run the api server
EXPOSE 80
# CMD ["gunicorn", "--bind", "0.0.0.0:80", "--workers", "2", "lexi.serve:app"]
# CMD ["gunicorn",  "lexi.serve:app"]
# CMD ["gunicorn", "--worker-class", "gevent", "--worker-connections", "2", "--bind", "0.0.0.0:80", "lexi.serve:app"]
CMD ["gunicorn", "--worker-class", "gevent", "--worker-connections", "2", "-b", "0.0.0.0:8000", "lexi.serve:app"]
# CMD ["gunicorn", "--worker-class", "gevent", "--worker-connections", "2", "-b", "0.0.0.0:8000", "lexi.server.serve:app"]