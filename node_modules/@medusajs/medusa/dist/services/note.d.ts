import { EntityManager } from "typeorm";
import { TransactionBaseService } from "../interfaces";
import { NoteRepository } from "../repositories/note";
import EventBusService from "./event-bus";
import { FindConfig, Selector } from "../types/common";
import { Note } from "../models";
import { CreateNoteInput } from "../types/note";
declare type InjectedDependencies = {
    manager: EntityManager;
    noteRepository: typeof NoteRepository;
    eventBusService: EventBusService;
};
declare class NoteService extends TransactionBaseService {
    static readonly Events: {
        CREATED: string;
        UPDATED: string;
        DELETED: string;
    };
    protected manager_: EntityManager;
    protected transactionManager_: EntityManager | undefined;
    protected readonly noteRepository_: typeof NoteRepository;
    protected readonly eventBus_: EventBusService;
    constructor({ manager, noteRepository, eventBusService, }: InjectedDependencies);
    /**
     * Retrieves a specific note.
     * @param id - the id of the note to retrieve.
     * @param config - any options needed to query for the result.
     * @return which resolves to the requested note.
     */
    retrieve(id: string, config?: FindConfig<Note>): Promise<Note | never>;
    /** Fetches all notes related to the given selector
     * @param selector - the query object for find
     * @param config - the configuration used to find the objects. contains relations, skip, and take.
     * @param config.relations - Which relations to include in the resulting list of Notes.
     * @param config.take - How many Notes to take in the resulting list of Notes.
     * @param config.skip - How many Notes to skip in the resulting list of Notes.
     * @return notes related to the given search.
     */
    list(selector: Selector<Note>, config?: FindConfig<Note>): Promise<Note[]>;
    /**
     * Creates a note associated with a given author
     * @param data - the note to create
     * @param config - any configurations if needed, including meta data
     * @return resolves to the creation result
     */
    create(data: CreateNoteInput, config?: {
        metadata: Record<string, unknown>;
    }): Promise<Note>;
    /**
     * Updates a given note with a new value
     * @param noteId - the id of the note to update
     * @param value - the new value
     * @return resolves to the updated element
     */
    update(noteId: string, value: string): Promise<Note>;
    /**
     * Deletes a given note
     * @param noteId - id of the note to delete
     */
    delete(noteId: string): Promise<void>;
}
export default NoteService;
