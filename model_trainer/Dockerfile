# syntax=docker/dockerfile:1
FROM jupyter/scipy-notebook:latest

USER root
WORKDIR /home/jovyan/work

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER $NB_UID
CMD ["start-notebook.sh", "--NotebookApp.token=matkhau123", "--NotebookApp.notebook_dir=/home/jovyan/work"]
