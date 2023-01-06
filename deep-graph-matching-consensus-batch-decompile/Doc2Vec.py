import gensim
import pickle
import datetime

def Doc2VecModelBuilding(subject_path):

    print('Start reading the corpus')
    sentences=gensim.models.doc2vec.TaggedLineDocument(subject_path+'ALLCorpus.txt')


    print('Start building the model')
    time_1=datetime.datetime.now()
    model=gensim.models.Doc2Vec(sentences,dm=1,vector_size=128,window=5)
    time_2=datetime.datetime.now()
    print("Total elapse time for building the model (s): "+str((time_2-time_1).total_seconds()))

    print('Start Training')
    time_1=datetime.datetime.now()
    model.train(sentences,total_examples=model.corpus_count,epochs=20)
    # print(model.get_latest_training_loss())
    time_2=datetime.datetime.now()
    print("Total elapse time for training (s): "+str((time_2-time_1).total_seconds()))

    f_model=open(subject_path+'Doc2Vec_Model.pkl','wb')
    pickle.dump(model, f_model, protocol = 4)